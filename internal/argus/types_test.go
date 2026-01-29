// ABOUTME: Unit tests for Argus worker types and validation
// ABOUTME: Tests task messages, scanner status, and result structures

package argus

import (
	"encoding/json"
	"testing"
	"time"
)

func TestArgusTaskMessage_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		msg     TaskMessage
		wantErr bool
	}{
		{
			name: "valid message",
			msg: TaskMessage{
				JobID:          "job-123",
				ReportID:       "report-456",
				OrganizationID: "org-789",
				ParentTaskID:   "parent-001",
				GCSURI:         "gs://bucket/org-789/skills/skill.zip",
				Scanners:       []string{"trivy", "clamav"},
				CreatedAt:      time.Now(),
			},
			wantErr: false,
		},
		{
			name: "missing job id",
			msg: TaskMessage{
				ReportID:       "report-456",
				OrganizationID: "org-789",
				GCSURI:         "gs://bucket/org-789/skills/skill.zip",
				Scanners:       []string{"trivy"},
			},
			wantErr: true,
		},
		{
			name: "missing gcs uri",
			msg: TaskMessage{
				JobID:          "job-123",
				OrganizationID: "org-789",
				Scanners:       []string{"trivy"},
			},
			wantErr: true,
		},
		{
			name: "empty scanners",
			msg: TaskMessage{
				JobID:          "job-123",
				OrganizationID: "org-789",
				GCSURI:         "gs://bucket/org-789/skills/skill.zip",
				Scanners:       []string{},
			},
			wantErr: true,
		},
		{
			name: "invalid scanner",
			msg: TaskMessage{
				JobID:          "job-123",
				OrganizationID: "org-789",
				GCSURI:         "gs://bucket/org-789/skills/skill.zip",
				Scanners:       []string{"invalid"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.msg.Validate()
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

func TestScannerStatus_Valid(t *testing.T) {
	t.Parallel()

	validStatuses := []ScannerStatus{
		StatusPending,
		StatusRunning,
		StatusCompleted,
		StatusFailed,
	}

	for _, status := range validStatuses {
		if !status.IsValid() {
			t.Errorf("IsValid() = false for %q, want true", status)
		}
	}

	invalidStatus := ScannerStatus("invalid")
	if invalidStatus.IsValid() {
		t.Error("IsValid() = true for invalid status, want false")
	}
}

func TestScannerStatus_IsTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   ScannerStatus
		terminal bool
	}{
		{StatusPending, false},
		{StatusRunning, false},
		{StatusCompleted, true},
		{StatusFailed, true},
	}

	for _, tt := range tests {
		if got := tt.status.IsTerminal(); got != tt.terminal {
			t.Errorf("%q.IsTerminal() = %v, want %v", tt.status, got, tt.terminal)
		}
	}
}

func TestArgusStatus_AllTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   ArgusStatus
		terminal bool
	}{
		{
			name:     "all pending",
			status:   ArgusStatus{Trivy: StatusPending, ClamAV: StatusPending},
			terminal: false,
		},
		{
			name:     "mixed",
			status:   ArgusStatus{Trivy: StatusCompleted, ClamAV: StatusRunning},
			terminal: false,
		},
		{
			name:     "all completed",
			status:   ArgusStatus{Trivy: StatusCompleted, ClamAV: StatusCompleted},
			terminal: true,
		},
		{
			name:     "one failed",
			status:   ArgusStatus{Trivy: StatusCompleted, ClamAV: StatusFailed},
			terminal: true,
		},
		{
			name:     "all failed",
			status:   ArgusStatus{Trivy: StatusFailed, ClamAV: StatusFailed},
			terminal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.status.AllTerminal(); got != tt.terminal {
				t.Errorf("AllTerminal() = %v, want %v", got, tt.terminal)
			}
		})
	}
}

func TestTaskMessage_JSON(t *testing.T) {
	t.Parallel()

	msg := TaskMessage{
		JobID:          "job-123",
		ReportID:       "report-456",
		OrganizationID: "org-789",
		ParentTaskID:   "parent-001",
		GCSURI:         "gs://bucket/org-789/skills/skill.zip",
		Scanners:       []string{"trivy", "clamav"},
		RetryCount:     0,
		TimeoutSeconds: 900,
		TTLSeconds:     86400,
		CreatedAt:      time.Date(2026, 1, 29, 12, 0, 0, 0, time.UTC),
	}

	// Marshal.
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal.
	var got TaskMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Verify.
	if got.JobID != msg.JobID {
		t.Errorf("JobID = %q, want %q", got.JobID, msg.JobID)
	}
	if got.GCSURI != msg.GCSURI {
		t.Errorf("GCSURI = %q, want %q", got.GCSURI, msg.GCSURI)
	}
	if len(got.Scanners) != len(msg.Scanners) {
		t.Errorf("Scanners length = %d, want %d", len(got.Scanners), len(msg.Scanners))
	}
}

func TestArgusResults_HasErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		results   ArgusResults
		hasErrors bool
	}{
		{
			name:      "no errors",
			results:   ArgusResults{},
			hasErrors: false,
		},
		{
			name: "with errors",
			results: ArgusResults{
				Errors: map[string]string{"trivy": "timeout"},
			},
			hasErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.results.HasErrors(); got != tt.hasErrors {
				t.Errorf("HasErrors() = %v, want %v", got, tt.hasErrors)
			}
		})
	}
}

func TestInfectedFile(t *testing.T) {
	t.Parallel()

	file := InfectedFile{
		Path:       "/tmp/skills/malware.exe",
		ThreatName: "Trojan.Generic",
		Hash:       "abc123",
	}

	if file.Path != "/tmp/skills/malware.exe" {
		t.Errorf("Path = %q, want %q", file.Path, "/tmp/skills/malware.exe")
	}
}

func TestTrivyResults_VulnCount(t *testing.T) {
	t.Parallel()

	results := TrivyResults{
		Summary: TrivySummary{
			TotalVulnerabilities: 5,
			Critical:             1,
			High:                 2,
			Medium:               1,
			Low:                  1,
		},
	}

	if results.Summary.TotalVulnerabilities != 5 {
		t.Errorf("TotalVulnerabilities = %d, want 5", results.Summary.TotalVulnerabilities)
	}
}
