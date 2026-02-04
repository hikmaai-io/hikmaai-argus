// ABOUTME: HTTP handlers for hikmaai-argus API endpoints
// ABOUTME: Provides hash lookup, file upload scanning, and job polling

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/scanner"
	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// DBUpdateStatusProvider provides status information about database updates.
type DBUpdateStatusProvider interface {
	GetStatus() map[string]*DBUpdateStatus
}

// DBUpdateStatus contains the status of a single database updater.
type DBUpdateStatus struct {
	Name          string     `json:"name"`
	Status        string     `json:"status"` // idle, updating, failed
	Ready         bool       `json:"ready"`
	LastUpdate    *time.Time `json:"last_update,omitempty"`
	NextScheduled *time.Time `json:"next_scheduled,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	Version       int        `json:"version,omitempty"`
}

// Handler provides HTTP handlers for the API.
type Handler struct {
	engine           *engine.Engine
	jobStore         *engine.JobStore
	scanCache        *engine.ScanCache
	worker           *scanner.Worker
	uploadDir        string
	maxFileSize      int64
	trivyScanner     *trivy.Scanner
	trivyJobStore    *TrivyJobStore
	dbUpdateProvider DBUpdateStatusProvider
}

// HandlerConfig holds configuration for API handlers.
type HandlerConfig struct {
	Engine           *engine.Engine
	JobStore         *engine.JobStore
	ScanCache        *engine.ScanCache
	Worker           *scanner.Worker
	UploadDir        string
	MaxFileSize      int64
	TrivyScanner     *trivy.Scanner
	TrivyJobStore    *TrivyJobStore
	DBUpdateProvider DBUpdateStatusProvider
}

// NewHandler creates a new API handler.
func NewHandler(cfg HandlerConfig) *Handler {
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 100 * 1024 * 1024 // 100MB default
	}
	return &Handler{
		engine:           cfg.Engine,
		jobStore:         cfg.JobStore,
		scanCache:        cfg.ScanCache,
		worker:           cfg.Worker,
		uploadDir:        cfg.UploadDir,
		maxFileSize:      cfg.MaxFileSize,
		trivyScanner:     cfg.TrivyScanner,
		trivyJobStore:    cfg.TrivyJobStore,
		dbUpdateProvider: cfg.DBUpdateProvider,
	}
}

// RegisterRoutes registers all API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/files/{hash}", h.HandleGetFileByHash)
	mux.HandleFunc("POST /api/v1/files", h.HandleUploadFile)
	mux.HandleFunc("GET /api/v1/jobs/{id}", h.HandleGetJob)
	mux.HandleFunc("GET /api/v1/health", h.HandleHealth)

	// Trivy dependency scanning endpoints.
	mux.HandleFunc("POST /api/v1/dependencies/scan", h.HandleDependencyScan)
	mux.HandleFunc("GET /api/v1/dependencies/jobs/{id}", h.HandleGetDependencyJob)
}

// HandleGetFileByHash handles hash lookup requests.
// GET /api/v1/files/{hash}
func (h *Handler) HandleGetFileByHash(w http.ResponseWriter, r *http.Request) {
	hashStr := r.PathValue("hash")
	if hashStr == "" {
		writeError(w, http.StatusBadRequest, "hash is required")
		return
	}

	hash, err := types.ParseHash(hashStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid hash: %v", err))
		return
	}

	result, err := h.engine.Lookup(r.Context(), hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("lookup failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// HandleUploadFile handles file upload for scanning.
// POST /api/v1/files
// Returns 202 Accepted with job ID for polling.
func (h *Handler) HandleUploadFile(w http.ResponseWriter, r *http.Request) {
	// Limit request body size.
	r.Body = http.MaxBytesReader(w, r.Body, h.maxFileSize)

	// Parse multipart form.
	if err := r.ParseMultipartForm(h.maxFileSize); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("parsing form: %v", err))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("reading file: %v", err))
		return
	}
	defer file.Close()

	// Hash the file while saving it.
	hasher := sha256.New()
	teeReader := io.TeeReader(file, hasher)

	// Create upload directory if needed.
	if err := os.MkdirAll(h.uploadDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("creating upload dir: %v", err))
		return
	}

	// Save to temporary file.
	tempFile, err := os.CreateTemp(h.uploadDir, "upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("creating temp file: %v", err))
		return
	}
	uploadPath := tempFile.Name()

	// Clean up temp file on error.
	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			os.Remove(uploadPath)
		}
	}()

	written, err := io.Copy(tempFile, teeReader)
	if err != nil {
		tempFile.Close()
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("saving file: %v", err))
		return
	}
	tempFile.Close()

	fileHash := hex.EncodeToString(hasher.Sum(nil))

	// Check cache for existing result.
	if h.scanCache != nil {
		cached, found, _ := h.scanCache.Get(r.Context(), fileHash)
		if found {
			// Return cached result immediately.
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"cached": true,
				"result": cached,
			})
			return
		}
	}

	// Check for existing pending/running job for this hash.
	if h.jobStore != nil {
		existingJob, _ := h.jobStore.GetByFileHash(r.Context(), fileHash)
		if existingJob != nil && !existingJob.Status.IsTerminal() {
			// Return existing job ID for polling.
			writeJSON(w, http.StatusAccepted, map[string]interface{}{
				"job_id":  existingJob.ID,
				"status":  existingJob.Status,
				"message": "scan already in progress",
			})
			return
		}
	}

	// Create new job.
	job := types.NewJob(fileHash, header.Filename, written)

	if h.jobStore != nil {
		if err := h.jobStore.Create(r.Context(), job); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("creating job: %v", err))
			return
		}
	}

	// Submit job to worker.
	if h.worker != nil {
		if err := h.worker.Submit(job.ID, uploadPath); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("queueing job: %v", err))
			return
		}
		cleanupTemp = false // Worker will handle cleanup.
	}

	// Return 202 Accepted with job ID.
	w.Header().Set("Location", fmt.Sprintf("/api/v1/jobs/%s", job.ID))
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id":    job.ID,
		"status":    job.Status,
		"file_hash": fileHash,
		"file_size": written,
		"message":   "scan queued",
	})
}

// HandleGetJob handles job status polling.
// GET /api/v1/jobs/{id}
func (h *Handler) HandleGetJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	if jobID == "" {
		writeError(w, http.StatusBadRequest, "job ID is required")
		return
	}

	job, err := h.jobStore.Get(r.Context(), jobID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("getting job: %v", err))
		return
	}
	if job == nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	writeJSON(w, http.StatusOK, job)
}

// HandleHealth handles health check requests.
// GET /api/v1/health
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	checks := make(map[string]interface{})

	// Check engine.
	if h.engine != nil {
		stats, err := h.engine.Stats(r.Context())
		if err != nil {
			status = "degraded"
			checks["engine"] = fmt.Sprintf("error: %v", err)
		} else {
			checks["engine"] = fmt.Sprintf("ok (signatures: %d)", stats.SignatureCount)
		}
	}

	// Check job store.
	if h.jobStore != nil {
		count, err := h.jobStore.Count(r.Context())
		if err != nil {
			checks["job_store"] = fmt.Sprintf("error: %v", err)
		} else {
			checks["job_store"] = fmt.Sprintf("ok (jobs: %d)", count)
		}
	}

	// Check worker queue.
	if h.worker != nil {
		checks["worker"] = fmt.Sprintf("ok (queue: %d)", h.worker.QueueLength())
	}

	// Include DB update status if provider is configured.
	if h.dbUpdateProvider != nil {
		dbStatus := h.dbUpdateProvider.GetStatus()
		if len(dbStatus) > 0 {
			checks["db_updates"] = dbStatus
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().UTC(),
		"checks":    checks,
	})
}

// HandleDependencyScan handles dependency vulnerability scan requests.
// POST /api/v1/dependencies/scan
// Returns 202 Accepted with job ID for polling.
func (h *Handler) HandleDependencyScan(w http.ResponseWriter, r *http.Request) {
	if h.trivyScanner == nil {
		writeError(w, http.StatusServiceUnavailable, "trivy scanning is not enabled")
		return
	}

	// Parse request body.
	var req trivy.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// Validate request.
	if err := req.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("validation error: %v", err))
		return
	}

	// Create job.
	jobID := uuid.New().String()
	job := &TrivyJob{
		ID:             jobID,
		Status:         "pending",
		Packages:       req.Packages,
		SeverityFilter: req.SeverityFilter,
		CreatedAt:      time.Now(),
	}

	// Store job.
	if h.trivyJobStore != nil {
		h.trivyJobStore.Set(jobID, job)
	}

	// Process scan asynchronously.
	go h.processTrivyScan(job)

	// Return 202 Accepted.
	w.Header().Set("Location", fmt.Sprintf("/api/v1/dependencies/jobs/%s", jobID))
	writeJSON(w, http.StatusAccepted, trivy.JobResponse{
		JobID:   jobID,
		Status:  "pending",
		Message: "vulnerability scan queued",
	})
}

// processTrivyScan performs the Trivy scan in the background.
func (h *Handler) processTrivyScan(job *TrivyJob) {
	ctx := context.Background()

	// Update status to running.
	job.Status = "running"
	now := time.Now()
	job.StartedAt = &now
	if h.trivyJobStore != nil {
		h.trivyJobStore.Set(job.ID, job)
	}

	// Perform scan.
	result, err := h.trivyScanner.ScanPackages(ctx, job.Packages, job.SeverityFilter)

	completed := time.Now()
	job.CompletedAt = &completed

	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
	} else {
		job.Status = "completed"
		job.Result = result
	}

	// Update final status.
	if h.trivyJobStore != nil {
		h.trivyJobStore.Set(job.ID, job)
	}
}

// HandleGetDependencyJob handles dependency scan job status polling.
// GET /api/v1/dependencies/jobs/{id}
func (h *Handler) HandleGetDependencyJob(w http.ResponseWriter, r *http.Request) {
	if h.trivyJobStore == nil {
		writeError(w, http.StatusServiceUnavailable, "trivy scanning is not enabled")
		return
	}

	jobID := r.PathValue("id")
	if jobID == "" {
		writeError(w, http.StatusBadRequest, "job ID is required")
		return
	}

	job, found := h.trivyJobStore.Get(jobID)
	if !found {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	// Build response based on job status.
	resp := trivy.JobStatusResponse{
		JobID:  job.ID,
		Status: job.Status,
	}

	if job.Result != nil {
		resp.Summary = &job.Result.Summary
		resp.Vulnerabilities = job.Result.Vulnerabilities
		resp.ScannedAt = &job.Result.ScannedAt
	}

	if job.Error != "" {
		resp.Error = job.Error
	}

	writeJSON(w, http.StatusOK, resp)
}

// TrivyJob represents an async dependency scan job.
type TrivyJob struct {
	ID             string            `json:"id"`
	Status         string            `json:"status"`
	Packages       []trivy.Package   `json:"packages"`
	SeverityFilter []string          `json:"severity_filter,omitempty"`
	Result         *trivy.ScanResult `json:"result,omitempty"`
	Error          string            `json:"error,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	StartedAt      *time.Time        `json:"started_at,omitempty"`
	CompletedAt    *time.Time        `json:"completed_at,omitempty"`
}

// TrivyJobStore is an in-memory store for Trivy scan jobs.
// For production, this should be replaced with persistent storage.
type TrivyJobStore struct {
	mu   sync.RWMutex
	jobs map[string]*TrivyJob
}

// NewTrivyJobStore creates a new in-memory job store.
func NewTrivyJobStore() *TrivyJobStore {
	return &TrivyJobStore{
		jobs: make(map[string]*TrivyJob),
	}
}

// Set stores a job.
func (s *TrivyJobStore) Set(id string, job *TrivyJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[id] = job
}

// Get retrieves a job by ID.
func (s *TrivyJobStore) Get(id string) (*TrivyJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	return job, ok
}

// Delete removes a job.
func (s *TrivyJobStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.jobs, id)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}

// Middleware for logging requests.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)

		// Skip logging for health checks.
		if !strings.HasSuffix(r.URL.Path, "/health") {
			fmt.Printf("%s %s %s\n", r.Method, r.URL.Path, duration)
		}
	})
}

// CleanupUploadedFile removes a temporary uploaded file.
func CleanupUploadedFile(path string) {
	if path != "" && filepath.Dir(path) != "/" {
		os.Remove(path)
	}
}
