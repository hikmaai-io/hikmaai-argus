// ABOUTME: Tests for Job type used in async scan operations
// ABOUTME: Validates job lifecycle, status transitions, and constructors

package types

import (
	"testing"
	"time"
)

func TestJobStatus_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status JobStatus
		want   string
	}{
		{name: "pending", status: JobStatusPending, want: "pending"},
		{name: "running", status: JobStatusRunning, want: "running"},
		{name: "completed", status: JobStatusCompleted, want: "completed"},
		{name: "failed", status: JobStatusFailed, want: "failed"},
		{name: "unknown default", status: JobStatus("invalid"), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.String(); got != tt.want {
				t.Errorf("JobStatus.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJobStatus_IsTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status JobStatus
		want   bool
	}{
		{name: "pending is not terminal", status: JobStatusPending, want: false},
		{name: "running is not terminal", status: JobStatusRunning, want: false},
		{name: "completed is terminal", status: JobStatusCompleted, want: true},
		{name: "failed is terminal", status: JobStatusFailed, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsTerminal(); got != tt.want {
				t.Errorf("JobStatus.IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewJob(t *testing.T) {
	t.Parallel()

	job := NewJob("abc123hash", "malware.exe", 2048)

	if job.ID == "" {
		t.Error("Job ID should not be empty")
	}
	if len(job.ID) != 36 { // UUID format
		t.Errorf("Job ID should be UUID format, got length %d", len(job.ID))
	}
	if job.Status != JobStatusPending {
		t.Errorf("Status = %v, want %v", job.Status, JobStatusPending)
	}
	if job.FileHash != "abc123hash" {
		t.Errorf("FileHash = %q, want %q", job.FileHash, "abc123hash")
	}
	if job.FileName != "malware.exe" {
		t.Errorf("FileName = %q, want %q", job.FileName, "malware.exe")
	}
	if job.FileSize != 2048 {
		t.Errorf("FileSize = %d, want %d", job.FileSize, 2048)
	}
	if job.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if job.CompletedAt != nil {
		t.Error("CompletedAt should be nil for new job")
	}
	if job.Result != nil {
		t.Error("Result should be nil for new job")
	}
}

func TestJob_Start(t *testing.T) {
	t.Parallel()

	job := NewJob("hash123", "file.exe", 1024)

	err := job.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if job.Status != JobStatusRunning {
		t.Errorf("Status = %v, want %v", job.Status, JobStatusRunning)
	}
	if job.StartedAt == nil {
		t.Error("StartedAt should be set after Start()")
	}
}

func TestJob_Start_InvalidTransition(t *testing.T) {
	t.Parallel()

	job := NewJob("hash123", "file.exe", 1024)
	job.Status = JobStatusCompleted

	err := job.Start()
	if err == nil {
		t.Error("Start() should fail for completed job")
	}
}

func TestJob_Complete(t *testing.T) {
	t.Parallel()

	job := NewJob("hash123", "file.exe", 1024)
	_ = job.Start()

	result := NewCleanScanResult("/path/to/file.exe", "hash123", 1024)
	err := job.Complete(result)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}

	if job.Status != JobStatusCompleted {
		t.Errorf("Status = %v, want %v", job.Status, JobStatusCompleted)
	}
	if job.Result == nil {
		t.Error("Result should be set after Complete()")
	}
	if job.CompletedAt == nil {
		t.Error("CompletedAt should be set after Complete()")
	}
}

func TestJob_Complete_InvalidTransition(t *testing.T) {
	t.Parallel()

	job := NewJob("hash123", "file.exe", 1024)
	// Job is still pending, not running

	result := NewCleanScanResult("/path/to/file.exe", "hash123", 1024)
	err := job.Complete(result)
	if err == nil {
		t.Error("Complete() should fail for pending job")
	}
}

func TestJob_Fail(t *testing.T) {
	t.Parallel()

	job := NewJob("hash123", "file.exe", 1024)
	_ = job.Start()

	err := job.Fail("connection timeout")
	if err != nil {
		t.Fatalf("Fail() error = %v", err)
	}

	if job.Status != JobStatusFailed {
		t.Errorf("Status = %v, want %v", job.Status, JobStatusFailed)
	}
	if job.Error != "connection timeout" {
		t.Errorf("Error = %q, want %q", job.Error, "connection timeout")
	}
	if job.CompletedAt == nil {
		t.Error("CompletedAt should be set after Fail()")
	}
}

func TestJob_Fail_FromPending(t *testing.T) {
	t.Parallel()

	job := NewJob("hash123", "file.exe", 1024)
	// Can fail from pending (e.g., validation error before start)

	err := job.Fail("file too large")
	if err != nil {
		t.Fatalf("Fail() error = %v", err)
	}

	if job.Status != JobStatusFailed {
		t.Errorf("Status = %v, want %v", job.Status, JobStatusFailed)
	}
}

func TestJob_Fail_InvalidTransition(t *testing.T) {
	t.Parallel()

	job := NewJob("hash123", "file.exe", 1024)
	job.Status = JobStatusCompleted

	err := job.Fail("some error")
	if err == nil {
		t.Error("Fail() should fail for completed job")
	}
}

func TestJob_Duration(t *testing.T) {
	t.Parallel()

	job := NewJob("hash123", "file.exe", 1024)

	// Duration should be 0 for non-started job
	if job.Duration() != 0 {
		t.Errorf("Duration() = %v, want 0 for pending job", job.Duration())
	}

	_ = job.Start()
	time.Sleep(10 * time.Millisecond)

	// Duration should be positive for running job
	if job.Duration() <= 0 {
		t.Error("Duration() should be positive for running job")
	}

	result := NewCleanScanResult("/path/to/file.exe", "hash123", 1024)
	_ = job.Complete(result)

	finalDuration := job.Duration()
	time.Sleep(10 * time.Millisecond)

	// Duration should be frozen for completed job
	if job.Duration() != finalDuration {
		t.Error("Duration() should be frozen for completed job")
	}
}

func TestJob_CreatedAtIsUTC(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC()
	job := NewJob("hash123", "file.exe", 1024)
	after := time.Now().UTC()

	if job.CreatedAt.Location() != time.UTC {
		t.Error("CreatedAt should be in UTC")
	}
	if job.CreatedAt.Before(before) || job.CreatedAt.After(after) {
		t.Errorf("CreatedAt = %v, should be between %v and %v", job.CreatedAt, before, after)
	}
}
