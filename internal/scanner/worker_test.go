// ABOUTME: Tests for background scan worker processing jobs asynchronously
// ABOUTME: Validates job processing, result caching, and signature persistence

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/config"
	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestWorker_ProcessJob(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if clamscan is available.
	if !isClamscanAvailable() {
		t.Skip("clamscan not found, skipping test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create test file.
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "clean.txt")
	if err := os.WriteFile(testFile, []byte("This is a clean file"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create worker dependencies.
	jobStore, err := engine.NewJobStore(engine.StoreConfig{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create job store: %v", err)
	}
	defer jobStore.Close()

	scanCache, err := engine.NewScanCache(engine.StoreConfig{InMemory: true}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create scan cache: %v", err)
	}
	defer scanCache.Close()

	scannerCfg := &config.ClamAVConfig{
		Mode:    "clamscan",
		Binary:  "clamscan",
		Timeout: 5 * time.Minute,
	}
	clamScanner := NewClamAVScanner(scannerCfg)

	worker := NewWorker(WorkerConfig{
		Scanner:   clamScanner,
		JobStore:  jobStore,
		ScanCache: scanCache,
	})

	// Create a job.
	job := types.NewJob("test-hash", "clean.txt", 21)
	if err := jobStore.Create(ctx, job); err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	// Process the job.
	err = worker.ProcessJob(ctx, job.ID, testFile)
	if err != nil {
		t.Fatalf("ProcessJob() error = %v", err)
	}

	// Verify job status.
	updatedJob, err := jobStore.Get(ctx, job.ID)
	if err != nil {
		t.Fatalf("Failed to get updated job: %v", err)
	}

	if updatedJob.Status != types.JobStatusCompleted {
		t.Errorf("Job status = %v, want %v", updatedJob.Status, types.JobStatusCompleted)
	}
	if updatedJob.Result == nil {
		t.Fatal("Job result should not be nil")
	}
	if updatedJob.Result.Status != types.ScanStatusClean {
		t.Errorf("Result status = %v, want %v", updatedJob.Result.Status, types.ScanStatusClean)
	}
}

func TestWorker_ProcessJob_Cached(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create worker dependencies.
	jobStore, err := engine.NewJobStore(engine.StoreConfig{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create job store: %v", err)
	}
	defer jobStore.Close()

	scanCache, err := engine.NewScanCache(engine.StoreConfig{InMemory: true}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create scan cache: %v", err)
	}
	defer scanCache.Close()

	// Pre-populate cache.
	cachedResult := types.NewCleanScanResult("/path/to/file", "cached-hash", 1024)
	if err := scanCache.Put(ctx, "cached-hash", cachedResult); err != nil {
		t.Fatalf("Failed to cache result: %v", err)
	}

	// Create worker without scanner (shouldn't need it due to cache hit).
	worker := NewWorker(WorkerConfig{
		Scanner:   nil, // Will fail if actually used.
		JobStore:  jobStore,
		ScanCache: scanCache,
	})

	// Create a job for the cached hash.
	job := types.NewJob("cached-hash", "cached.txt", 1024)
	if err := jobStore.Create(ctx, job); err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	// Process the job (should use cache).
	err = worker.ProcessJob(ctx, job.ID, "/any/path")
	if err != nil {
		t.Fatalf("ProcessJob() error = %v", err)
	}

	// Verify job completed with cached result.
	updatedJob, err := jobStore.Get(ctx, job.ID)
	if err != nil {
		t.Fatalf("Failed to get updated job: %v", err)
	}

	if updatedJob.Status != types.JobStatusCompleted {
		t.Errorf("Job status = %v, want %v", updatedJob.Status, types.JobStatusCompleted)
	}
}

func TestWorker_ProcessJob_NotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	jobStore, err := engine.NewJobStore(engine.StoreConfig{InMemory: true})
	if err != nil {
		t.Fatalf("Failed to create job store: %v", err)
	}
	defer jobStore.Close()

	worker := NewWorker(WorkerConfig{
		JobStore: jobStore,
	})

	// Try to process non-existent job.
	err = worker.ProcessJob(ctx, "non-existent-id", "/any/path")
	if err == nil {
		t.Error("ProcessJob() should error for non-existent job")
	}
}

func isClamscanAvailable() bool {
	paths := []string{
		"/usr/bin/clamscan",
		"/usr/local/bin/clamscan",
		"/opt/homebrew/bin/clamscan",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
