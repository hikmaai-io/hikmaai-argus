// ABOUTME: Tests for API handlers including hash lookup and job polling
// ABOUTME: Validates request/response handling and error cases

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestHandler_HandleGetFileByHash(t *testing.T) {
	t.Parallel()

	eng := setupTestEngine(t)
	handler := NewHandler(HandlerConfig{Engine: eng})

	// Add a test signature.
	sig := &types.Signature{
		SHA256:        "a" + strings.Repeat("0", 63),
		DetectionName: "Test.Malware",
		ThreatType:    types.ThreatTypeMalware,
		Severity:      types.SeverityHigh,
		Source:        "test",
	}
	eng.AddSignature(context.Background(), sig)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Test found hash.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/files/"+sig.SHA256, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result types.Result
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("Decoding response: %v", err)
	}

	if result.Status != types.StatusMalware {
		t.Errorf("Result status = %v, want %v", result.Status, types.StatusMalware)
	}
}

func TestHandler_HandleGetFileByHash_NotFound(t *testing.T) {
	t.Parallel()

	eng := setupTestEngine(t)
	handler := NewHandler(HandlerConfig{Engine: eng})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/files/"+strings.Repeat("0", 64), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result types.Result
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("Decoding response: %v", err)
	}

	if result.Status != types.StatusUnknown {
		t.Errorf("Result status = %v, want %v", result.Status, types.StatusUnknown)
	}
}

func TestHandler_HandleGetFileByHash_InvalidHash(t *testing.T) {
	t.Parallel()

	eng := setupTestEngine(t)
	handler := NewHandler(HandlerConfig{Engine: eng})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/files/invalid", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandler_HandleGetJob(t *testing.T) {
	t.Parallel()

	jobStore := setupTestJobStore(t)
	handler := NewHandler(HandlerConfig{JobStore: jobStore})

	// Create a job.
	job := types.NewJob("testhash", "test.exe", 1024)
	if err := jobStore.Create(context.Background(), job); err != nil {
		t.Fatalf("Creating job: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+job.ID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	var returnedJob types.Job
	if err := json.NewDecoder(rec.Body).Decode(&returnedJob); err != nil {
		t.Fatalf("Decoding response: %v", err)
	}

	if returnedJob.ID != job.ID {
		t.Errorf("Job ID = %q, want %q", returnedJob.ID, job.ID)
	}
}

func TestHandler_HandleGetJob_NotFound(t *testing.T) {
	t.Parallel()

	jobStore := setupTestJobStore(t)
	handler := NewHandler(HandlerConfig{JobStore: jobStore})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandler_HandleUploadFile(t *testing.T) {
	t.Parallel()

	jobStore := setupTestJobStore(t)
	uploadDir := t.TempDir()

	handler := NewHandler(HandlerConfig{
		JobStore:    jobStore,
		UploadDir:   uploadDir,
		MaxFileSize: 10 * 1024 * 1024,
	})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Create multipart form.
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatalf("Creating form file: %v", err)
	}
	part.Write([]byte("test file content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("Status = %d, want %d; body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("Decoding response: %v", err)
	}

	if response["job_id"] == nil {
		t.Error("Response should contain job_id")
	}
	if response["file_hash"] == nil {
		t.Error("Response should contain file_hash")
	}
}

func TestHandler_HandleUploadFile_CacheHit(t *testing.T) {
	t.Parallel()

	jobStore := setupTestJobStore(t)
	scanCache := setupTestScanCache(t)
	uploadDir := t.TempDir()

	handler := NewHandler(HandlerConfig{
		JobStore:    jobStore,
		ScanCache:   scanCache,
		UploadDir:   uploadDir,
		MaxFileSize: 10 * 1024 * 1024,
	})

	// Pre-cache a result for the file content we'll upload.
	fileContent := []byte("cached file content")

	// Compute the actual hash.
	hasher := sha256.New()
	hasher.Write(fileContent)
	fileHash := hex.EncodeToString(hasher.Sum(nil))

	cachedResult := types.NewCleanScanResult("/path", fileHash, int64(len(fileContent)))
	scanCache.Put(context.Background(), fileHash, cachedResult)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Create multipart form.
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "cached.txt")
	part.Write(fileContent)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should return 200 OK with cached result.
	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("Decoding response: %v", err)
	}

	if response["cached"] != true {
		t.Error("Response should indicate cached result")
	}
}

func TestHandler_HandleHealth(t *testing.T) {
	t.Parallel()

	eng := setupTestEngine(t)
	handler := NewHandler(HandlerConfig{Engine: eng})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("Decoding response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("Status = %q, want %q", response["status"], "ok")
	}
}

// Test helpers.

func setupTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	eng, err := engine.NewEngine(engine.EngineConfig{
		StoreConfig: engine.StoreConfig{InMemory: true},
		BloomConfig: engine.BloomConfig{
			ExpectedItems:     1000,
			FalsePositiveRate: 0.01,
		},
	})
	if err != nil {
		t.Fatalf("Creating engine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })
	return eng
}

func setupTestJobStore(t *testing.T) *engine.JobStore {
	t.Helper()
	store, err := engine.NewJobStore(engine.StoreConfig{InMemory: true})
	if err != nil {
		t.Fatalf("Creating job store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func setupTestScanCache(t *testing.T) *engine.ScanCache {
	t.Helper()
	cache, err := engine.NewScanCache(engine.StoreConfig{InMemory: true}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Creating scan cache: %v", err)
	}
	t.Cleanup(func() { cache.Close() })
	return cache
}
