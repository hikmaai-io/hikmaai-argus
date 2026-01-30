// ABOUTME: Unit tests for Argus worker orchestrator
// ABOUTME: Tests task processing, state updates, and completion signals

package argus

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestWorkerConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     WorkerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: WorkerConfig{
				TaskQueue:        "argus_task_queue",
				ConsumerGroup:    "argus-workers",
				ConsumerName:     "worker-1",
				CompletionPrefix: "argus_completion",
				Workers:          2,
				DefaultTimeout:   15 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "missing task queue",
			cfg: WorkerConfig{
				ConsumerGroup: "workers",
				ConsumerName:  "worker-1",
			},
			wantErr: true,
		},
		{
			name: "missing consumer group",
			cfg: WorkerConfig{
				TaskQueue:    "queue",
				ConsumerName: "worker-1",
			},
			wantErr: true,
		},
		{
			name: "zero workers uses default",
			cfg: WorkerConfig{
				TaskQueue:        "queue",
				ConsumerGroup:    "group",
				ConsumerName:     "worker-1",
				CompletionPrefix: "complete",
				Workers:          0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Validate() error = %v", err)
			}
		})
	}
}

func TestParseTaskMessage(t *testing.T) {
	t.Parallel()

	msg := TaskMessage{
		JobID:          "job-123",
		ReportID:       "report-456",
		OrganizationID: "org-789",
		ParentTaskID:   "parent-001",
		GCSURI:         "gs://bucket/org-789/skills/skill.zip",
		Scanners:       []string{"trivy", "clamav"},
		TimeoutSeconds: 900,
		CreatedAt:      time.Now().UTC(),
	}

	// Marshal to JSON (simulating what would come from Redis).
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Parse the message.
	parsed, err := ParseTaskMessage(string(data))
	if err != nil {
		t.Fatalf("ParseTaskMessage() error = %v", err)
	}

	if parsed.JobID != msg.JobID {
		t.Errorf("JobID = %q, want %q", parsed.JobID, msg.JobID)
	}
	if parsed.GCSURI != msg.GCSURI {
		t.Errorf("GCSURI = %q, want %q", parsed.GCSURI, msg.GCSURI)
	}
	if len(parsed.Scanners) != 2 {
		t.Errorf("Scanners len = %d, want 2", len(parsed.Scanners))
	}
}

func TestParseTaskMessage_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"invalid json", "not json"},
		{"missing required", `{"job_id": ""}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseTaskMessage(tt.data)
			if err == nil {
				t.Error("ParseTaskMessage() expected error, got nil")
			}
		})
	}
}

func TestCompletionSignal_JSON(t *testing.T) {
	t.Parallel()

	signal := CompletionSignal{
		JobID:       "job-123",
		Status:      "completed",
		CompletedAt: time.Date(2026, 1, 29, 12, 0, 0, 0, time.UTC),
		Results: &ArgusResults{
			Trivy: &TrivyResults{
				Summary: TrivySummary{TotalVulnerabilities: 2},
			},
		},
	}

	data, err := json.Marshal(signal)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got CompletionSignal
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if got.JobID != signal.JobID {
		t.Errorf("JobID = %q, want %q", got.JobID, signal.JobID)
	}
	if got.Status != signal.Status {
		t.Errorf("Status = %q, want %q", got.Status, signal.Status)
	}
}

func TestInitialArgusStatus(t *testing.T) {
	t.Parallel()

	scanners := []string{"trivy", "clamav"}
	status := InitialArgusStatus(scanners)

	if status.Trivy != StatusPending {
		t.Errorf("Trivy status = %q, want %q", status.Trivy, StatusPending)
	}
	if status.ClamAV != StatusPending {
		t.Errorf("ClamAV status = %q, want %q", status.ClamAV, StatusPending)
	}
}

func TestInitialArgusStatus_TrivyOnly(t *testing.T) {
	t.Parallel()

	scanners := []string{"trivy"}
	status := InitialArgusStatus(scanners)

	if status.Trivy != StatusPending {
		t.Errorf("Trivy status = %q, want %q", status.Trivy, StatusPending)
	}
	// ClamAV not requested; should be empty or pending (implementation choice).
}

func TestTaskProcessor_Interface(t *testing.T) {
	t.Parallel()

	// Verify TaskProcessor interface is implementable.
	var _ TaskProcessor = &mockTaskProcessor{}
}

type mockTaskProcessor struct {
	ProcessFunc func(ctx context.Context, msg *TaskMessage) (*ArgusResults, error)
}

func (m *mockTaskProcessor) Process(ctx context.Context, msg *TaskMessage) (*ArgusResults, error) {
	if m.ProcessFunc != nil {
		return m.ProcessFunc(ctx, msg)
	}
	return &ArgusResults{}, nil
}

func TestStatusTransitions(t *testing.T) {
	t.Parallel()

	// Test valid transitions.
	status := ArgusStatus{
		Trivy:  StatusPending,
		ClamAV: StatusPending,
	}

	// Pending -> Running.
	status.Trivy = StatusRunning
	if status.AllTerminal() {
		t.Error("AllTerminal() should be false when Trivy is running")
	}

	// Running -> Completed.
	status.Trivy = StatusCompleted
	status.ClamAV = StatusCompleted
	if !status.AllTerminal() {
		t.Error("AllTerminal() should be true when all completed")
	}
}

func TestWorkerConfig_CancelPrefixDefault(t *testing.T) {
	t.Parallel()

	cfg := WorkerConfig{
		TaskQueue:     "queue",
		ConsumerGroup: "group",
		ConsumerName:  "worker-1",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if cfg.CancelPrefix != "argus_cancel" {
		t.Errorf("CancelPrefix = %q, want %q", cfg.CancelPrefix, "argus_cancel")
	}
}

func TestWorkerConfig_CancelPrefixCustom(t *testing.T) {
	t.Parallel()

	cfg := WorkerConfig{
		TaskQueue:     "queue",
		ConsumerGroup: "group",
		ConsumerName:  "worker-1",
		CancelPrefix:  "custom_cancel",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if cfg.CancelPrefix != "custom_cancel" {
		t.Errorf("CancelPrefix = %q, want %q", cfg.CancelPrefix, "custom_cancel")
	}
}

func TestCancelChannelName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cancelPrefix string
		jobID        string
		want         string
	}{
		{
			name:         "default prefix",
			cancelPrefix: "argus_cancel",
			jobID:        "job-123",
			want:         "argus_cancel:job-123",
		},
		{
			name:         "custom prefix",
			cancelPrefix: "custom",
			jobID:        "abc-456",
			want:         "custom:abc-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := CancelChannelName(tt.cancelPrefix, tt.jobID)
			if got != tt.want {
				t.Errorf("CancelChannelName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCancellationListener_StopCleanup(t *testing.T) {
	t.Parallel()

	// Test that stopFn can be called safely multiple times.
	listener := NewCancellationListener()

	// Call stop before any goroutine starts.
	listener.Stop()

	// Verify channel is closed.
	select {
	case <-listener.Done():
		// Expected; channel should be closed.
	default:
		t.Error("Done() channel should be closed after Stop()")
	}

	// Safe to call stop again.
	listener.Stop()
}

func TestCompletionSignal_Cancelled(t *testing.T) {
	t.Parallel()

	signal := CompletionSignal{
		JobID:       "job-cancelled",
		Status:      "cancelled",
		CompletedAt: time.Now().UTC(),
		Results:     nil,
	}

	data, err := json.Marshal(signal)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got CompletionSignal
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if got.Status != "cancelled" {
		t.Errorf("Status = %q, want %q", got.Status, "cancelled")
	}
}

func TestCancellationListener_SignalReceived(t *testing.T) {
	t.Parallel()

	listener := NewCancellationListener()

	// Initially not cancelled.
	select {
	case <-listener.Done():
		t.Error("Done() channel should not be closed initially")
	default:
		// Expected.
	}

	// Signal cancellation.
	listener.Stop()

	// Should now be cancelled.
	select {
	case <-listener.Done():
		// Expected.
	default:
		t.Error("Done() channel should be closed after Stop()")
	}
}
