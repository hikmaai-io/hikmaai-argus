// ABOUTME: HTTP handlers for hikma-av API endpoints
// ABOUTME: Provides hash lookup, file upload scanning, and job polling

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hikmaai-io/hikma-av/internal/engine"
	"github.com/hikmaai-io/hikma-av/internal/scanner"
	"github.com/hikmaai-io/hikma-av/internal/types"
)

// Handler provides HTTP handlers for the API.
type Handler struct {
	engine      *engine.Engine
	jobStore    *engine.JobStore
	scanCache   *engine.ScanCache
	worker      *scanner.Worker
	uploadDir   string
	maxFileSize int64
}

// HandlerConfig holds configuration for API handlers.
type HandlerConfig struct {
	Engine      *engine.Engine
	JobStore    *engine.JobStore
	ScanCache   *engine.ScanCache
	Worker      *scanner.Worker
	UploadDir   string
	MaxFileSize int64
}

// NewHandler creates a new API handler.
func NewHandler(cfg HandlerConfig) *Handler {
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 100 * 1024 * 1024 // 100MB default
	}
	return &Handler{
		engine:      cfg.Engine,
		jobStore:    cfg.JobStore,
		scanCache:   cfg.ScanCache,
		worker:      cfg.Worker,
		uploadDir:   cfg.UploadDir,
		maxFileSize: cfg.MaxFileSize,
	}
}

// RegisterRoutes registers all API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/files/{hash}", h.HandleGetFileByHash)
	mux.HandleFunc("POST /api/v1/files", h.HandleUploadFile)
	mux.HandleFunc("GET /api/v1/jobs/{id}", h.HandleGetJob)
	mux.HandleFunc("GET /api/v1/health", h.HandleHealth)
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
	checks := make(map[string]string)

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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().UTC(),
		"checks":    checks,
	})
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
