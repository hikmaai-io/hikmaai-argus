// ABOUTME: Job type for async scan operations with state machine
// ABOUTME: Tracks scan jobs from creation through completion or failure

package types

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// JobStatus represents the current state of a scan job.
type JobStatus string

const (
	// JobStatusPending indicates the job is queued but not yet started.
	JobStatusPending JobStatus = "pending"
	// JobStatusRunning indicates the job is currently being processed.
	JobStatusRunning JobStatus = "running"
	// JobStatusCompleted indicates the job finished successfully.
	JobStatusCompleted JobStatus = "completed"
	// JobStatusFailed indicates the job failed with an error.
	JobStatusFailed JobStatus = "failed"
)

// String returns the string representation of the job status.
func (s JobStatus) String() string {
	switch s {
	case JobStatusPending:
		return "pending"
	case JobStatusRunning:
		return "running"
	case JobStatusCompleted:
		return "completed"
	case JobStatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// IsTerminal returns true if the status is a final state (completed or failed).
func (s JobStatus) IsTerminal() bool {
	return s == JobStatusCompleted || s == JobStatusFailed
}

// Job represents an async scan job.
type Job struct {
	// Unique job identifier (UUID).
	ID string `json:"id"`

	// Current job status.
	Status JobStatus `json:"status"`

	// File information.
	FileHash string `json:"file_hash"` // SHA256
	FileName string `json:"file_name"`
	FileSize int64  `json:"file_size"`

	// Scan result (set when completed).
	Result *ScanResult `json:"result,omitempty"`

	// Error message (set when failed).
	Error string `json:"error,omitempty"`

	// Timestamps.
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// NewJob creates a new pending scan job.
func NewJob(fileHash, fileName string, fileSize int64) *Job {
	return &Job{
		ID:        uuid.New().String(),
		Status:    JobStatusPending,
		FileHash:  fileHash,
		FileName:  fileName,
		FileSize:  fileSize,
		CreatedAt: time.Now().UTC(),
	}
}

// Start transitions the job from pending to running.
func (j *Job) Start() error {
	if j.Status != JobStatusPending {
		return fmt.Errorf("cannot start job in %s status", j.Status)
	}
	now := time.Now().UTC()
	j.Status = JobStatusRunning
	j.StartedAt = &now
	return nil
}

// Complete transitions the job from running to completed with a result.
func (j *Job) Complete(result *ScanResult) error {
	if j.Status != JobStatusRunning {
		return fmt.Errorf("cannot complete job in %s status", j.Status)
	}
	now := time.Now().UTC()
	j.Status = JobStatusCompleted
	j.Result = result
	j.CompletedAt = &now
	return nil
}

// Fail transitions the job to failed with an error message.
// Can be called from pending (validation error) or running (scan error).
func (j *Job) Fail(errMsg string) error {
	if j.Status.IsTerminal() {
		return fmt.Errorf("cannot fail job in %s status", j.Status)
	}
	now := time.Now().UTC()
	j.Status = JobStatusFailed
	j.Error = errMsg
	j.CompletedAt = &now
	return nil
}

// Duration returns the job duration.
// For running jobs, returns time since start.
// For completed/failed jobs, returns total duration.
// For pending jobs, returns 0.
func (j *Job) Duration() time.Duration {
	if j.StartedAt == nil {
		return 0
	}
	if j.CompletedAt != nil {
		return j.CompletedAt.Sub(*j.StartedAt)
	}
	return time.Since(*j.StartedAt)
}
