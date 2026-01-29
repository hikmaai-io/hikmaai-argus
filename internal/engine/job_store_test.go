// ABOUTME: Tests for JobStore that persists scan jobs in BadgerDB
// ABOUTME: Validates CRUD operations and status-based listing

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestJobStore_Create(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	job := types.NewJob("abc123hash", "malware.exe", 2048)

	err := store.Create(context.Background(), job)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify job was stored.
	retrieved, err := store.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved.ID != job.ID {
		t.Errorf("ID = %q, want %q", retrieved.ID, job.ID)
	}
	if retrieved.FileHash != job.FileHash {
		t.Errorf("FileHash = %q, want %q", retrieved.FileHash, job.FileHash)
	}
	if retrieved.Status != types.JobStatusPending {
		t.Errorf("Status = %v, want %v", retrieved.Status, types.JobStatusPending)
	}
}

func TestJobStore_Get_NotFound(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	job, err := store.Get(context.Background(), "nonexistent-id")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if job != nil {
		t.Error("Get() should return nil for nonexistent job")
	}
}

func TestJobStore_Update(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	job := types.NewJob("abc123hash", "file.exe", 1024)
	if err := store.Create(context.Background(), job); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update job status.
	job.Start()
	if err := store.Update(context.Background(), job); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify update.
	retrieved, err := store.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved.Status != types.JobStatusRunning {
		t.Errorf("Status = %v, want %v", retrieved.Status, types.JobStatusRunning)
	}
	if retrieved.StartedAt == nil {
		t.Error("StartedAt should be set after Start()")
	}
}

func TestJobStore_Delete(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	job := types.NewJob("abc123hash", "file.exe", 1024)
	if err := store.Create(context.Background(), job); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Delete job.
	if err := store.Delete(context.Background(), job.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deletion.
	retrieved, err := store.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Get() should return nil after deletion")
	}
}

func TestJobStore_List_All(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	// Create jobs with different statuses.
	job1 := types.NewJob("hash1", "file1.exe", 1024)
	job2 := types.NewJob("hash2", "file2.exe", 2048)
	job3 := types.NewJob("hash3", "file3.exe", 4096)

	store.Create(context.Background(), job1)
	store.Create(context.Background(), job2)
	job3.Start()
	store.Create(context.Background(), job3)

	// List all jobs.
	jobs, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(jobs) != 3 {
		t.Errorf("List() returned %d jobs, want 3", len(jobs))
	}
}

func TestJobStore_List_ByStatus(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	// Create jobs with different statuses.
	job1 := types.NewJob("hash1", "file1.exe", 1024)
	job2 := types.NewJob("hash2", "file2.exe", 2048)
	job3 := types.NewJob("hash3", "file3.exe", 4096)

	store.Create(context.Background(), job1)

	job2.Start()
	store.Create(context.Background(), job2)

	job3.Start()
	job3.Complete(types.NewCleanScanResult("/path", "hash3", 4096))
	store.Create(context.Background(), job3)

	// List only pending jobs.
	pending, err := store.List(context.Background(), types.JobStatusPending)
	if err != nil {
		t.Fatalf("List(pending) error = %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("List(pending) returned %d jobs, want 1", len(pending))
	}

	// List only running jobs.
	running, err := store.List(context.Background(), types.JobStatusRunning)
	if err != nil {
		t.Fatalf("List(running) error = %v", err)
	}
	if len(running) != 1 {
		t.Errorf("List(running) returned %d jobs, want 1", len(running))
	}

	// List only completed jobs.
	completed, err := store.List(context.Background(), types.JobStatusCompleted)
	if err != nil {
		t.Fatalf("List(completed) error = %v", err)
	}
	if len(completed) != 1 {
		t.Errorf("List(completed) returned %d jobs, want 1", len(completed))
	}
}

func TestJobStore_GetByFileHash(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	job := types.NewJob("unique-file-hash", "file.exe", 1024)
	store.Create(context.Background(), job)

	// Find by file hash.
	found, err := store.GetByFileHash(context.Background(), "unique-file-hash")
	if err != nil {
		t.Fatalf("GetByFileHash() error = %v", err)
	}

	if found == nil {
		t.Fatal("GetByFileHash() returned nil, want job")
	}
	if found.ID != job.ID {
		t.Errorf("Found job ID = %q, want %q", found.ID, job.ID)
	}
}

func TestJobStore_GetByFileHash_NotFound(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	job, err := store.GetByFileHash(context.Background(), "nonexistent-hash")
	if err != nil {
		t.Fatalf("GetByFileHash() error = %v", err)
	}
	if job != nil {
		t.Error("GetByFileHash() should return nil for nonexistent hash")
	}
}

func TestJobStore_Cleanup(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	// Create old completed job.
	oldJob := types.NewJob("hash1", "old.exe", 1024)
	oldJob.Start()
	oldJob.Complete(types.NewCleanScanResult("/path", "hash1", 1024))
	// Simulate old job by backdating.
	oldTime := time.Now().Add(-48 * time.Hour)
	oldJob.CompletedAt = &oldTime
	store.Create(context.Background(), oldJob)

	// Create recent completed job.
	recentJob := types.NewJob("hash2", "recent.exe", 2048)
	recentJob.Start()
	recentJob.Complete(types.NewCleanScanResult("/path", "hash2", 2048))
	store.Create(context.Background(), recentJob)

	// Cleanup jobs older than 24 hours.
	deleted, err := store.Cleanup(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	if deleted != 1 {
		t.Errorf("Cleanup() deleted %d jobs, want 1", deleted)
	}

	// Old job should be gone.
	old, _ := store.Get(context.Background(), oldJob.ID)
	if old != nil {
		t.Error("Old job should be deleted")
	}

	// Recent job should still exist.
	recent, _ := store.Get(context.Background(), recentJob.ID)
	if recent == nil {
		t.Error("Recent job should still exist")
	}
}

func TestJobStore_Count(t *testing.T) {
	t.Parallel()

	store := setupTestJobStore(t)

	// Initially empty.
	count, err := store.Count(context.Background())
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 0 {
		t.Errorf("Count() = %d, want 0", count)
	}

	// Add jobs.
	store.Create(context.Background(), types.NewJob("hash1", "file1.exe", 1024))
	store.Create(context.Background(), types.NewJob("hash2", "file2.exe", 2048))

	count, err = store.Count(context.Background())
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 2 {
		t.Errorf("Count() = %d, want 2", count)
	}
}

// setupTestJobStore creates an in-memory job store for testing.
func setupTestJobStore(t *testing.T) *JobStore {
	t.Helper()

	store, err := NewJobStore(StoreConfig{InMemory: true})
	if err != nil {
		t.Fatalf("NewJobStore() error = %v", err)
	}

	t.Cleanup(func() {
		store.Close()
	})

	return store
}
