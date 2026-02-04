// ABOUTME: Tests for status tracking types and tracker
// ABOUTME: Validates status updates, version info, and thread-safe access

package dbupdater

import (
	"testing"
	"time"
)

func TestUpdaterStatus_IsReady(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status UpdaterStatus
		want   bool
	}{
		{
			name:   "default status is not ready",
			status: UpdaterStatus{},
			want:   false,
		},
		{
			name: "ready status",
			status: UpdaterStatus{
				Ready: true,
			},
			want: true,
		},
		{
			name: "not ready despite successful update",
			status: UpdaterStatus{
				Status: StatusIdle,
				Ready:  false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.status.IsReady(); got != tt.want {
				t.Errorf("IsReady() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdaterStatus_TimeSinceLastUpdate(t *testing.T) {
	t.Parallel()

	// Never updated.
	status := UpdaterStatus{}
	if d := status.TimeSinceLastUpdate(); d != 0 {
		t.Errorf("TimeSinceLastUpdate() for never updated = %v, want 0", d)
	}

	// Updated recently.
	status.LastUpdate = time.Now().Add(-5 * time.Minute)
	d := status.TimeSinceLastUpdate()
	if d < 4*time.Minute || d > 6*time.Minute {
		t.Errorf("TimeSinceLastUpdate() = %v, expected ~5 minutes", d)
	}
}

func TestStatusTracker_NewStatusTracker(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()
	if tracker == nil {
		t.Fatal("NewStatusTracker() returned nil")
	}

	// Should have no statuses initially.
	statuses := tracker.GetAll()
	if len(statuses) != 0 {
		t.Errorf("Initial GetAll() returned %d statuses, want 0", len(statuses))
	}
}

func TestStatusTracker_Register(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()

	tracker.Register("clamav")
	tracker.Register("trivy")

	statuses := tracker.GetAll()
	if len(statuses) != 2 {
		t.Errorf("GetAll() returned %d statuses, want 2", len(statuses))
	}

	// Check defaults.
	clamav := tracker.Get("clamav")
	if clamav == nil {
		t.Fatal("Get(clamav) returned nil")
	}
	if clamav.Name != "clamav" {
		t.Errorf("Name = %q, want %q", clamav.Name, "clamav")
	}
	if clamav.Status != StatusPending {
		t.Errorf("Status = %q, want %q", clamav.Status, StatusPending)
	}
	if clamav.Ready {
		t.Error("Ready should be false initially")
	}
}

func TestStatusTracker_SetStatus(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()
	tracker.Register("clamav")

	tracker.SetStatus("clamav", StatusUpdating)

	status := tracker.Get("clamav")
	if status.Status != StatusUpdating {
		t.Errorf("Status = %q, want %q", status.Status, StatusUpdating)
	}
}

func TestStatusTracker_SetReady(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()
	tracker.Register("clamav")

	tracker.SetReady("clamav", true)

	status := tracker.Get("clamav")
	if !status.Ready {
		t.Error("Ready should be true")
	}

	tracker.SetReady("clamav", false)

	status = tracker.Get("clamav")
	if status.Ready {
		t.Error("Ready should be false after setting to false")
	}
}

func TestStatusTracker_SetLastUpdate(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()
	tracker.Register("clamav")

	now := time.Now()
	tracker.SetLastUpdate("clamav", now)

	status := tracker.Get("clamav")
	if !status.LastUpdate.Equal(now) {
		t.Errorf("LastUpdate = %v, want %v", status.LastUpdate, now)
	}
}

func TestStatusTracker_SetNextScheduled(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()
	tracker.Register("trivy")

	next := time.Now().Add(1 * time.Hour)
	tracker.SetNextScheduled("trivy", next)

	status := tracker.Get("trivy")
	if !status.NextScheduled.Equal(next) {
		t.Errorf("NextScheduled = %v, want %v", status.NextScheduled, next)
	}
}

func TestStatusTracker_SetError(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()
	tracker.Register("clamav")

	tracker.SetError("clamav", "connection refused")

	status := tracker.Get("clamav")
	if status.LastError != "connection refused" {
		t.Errorf("LastError = %q, want %q", status.LastError, "connection refused")
	}

	// Clear error.
	tracker.SetError("clamav", "")
	status = tracker.Get("clamav")
	if status.LastError != "" {
		t.Errorf("LastError after clear = %q, want empty", status.LastError)
	}
}

func TestStatusTracker_SetVersion(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()
	tracker.Register("clamav")

	version := VersionInfo{
		Version:   12345,
		BuildTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		DBFiles: map[string]int{
			"main.cvd":  12345,
			"daily.cvd": 67890,
		},
	}
	tracker.SetVersion("clamav", version)

	status := tracker.Get("clamav")
	if status.Version.Version != 12345 {
		t.Errorf("Version.Version = %d, want 12345", status.Version.Version)
	}
	if len(status.Version.DBFiles) != 2 {
		t.Errorf("Version.DBFiles has %d entries, want 2", len(status.Version.DBFiles))
	}
}

func TestStatusTracker_Get_Nonexistent(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()

	status := tracker.Get("nonexistent")
	if status != nil {
		t.Error("Get() for nonexistent should return nil")
	}
}

func TestStatusTracker_SetStatus_Nonexistent(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()

	// Should not panic for nonexistent updater.
	tracker.SetStatus("nonexistent", StatusIdle)
	tracker.SetReady("nonexistent", true)
	tracker.SetError("nonexistent", "error")
}

func TestStatusTracker_GetAll_Copy(t *testing.T) {
	t.Parallel()

	tracker := NewStatusTracker()
	tracker.Register("clamav")
	tracker.SetStatus("clamav", StatusIdle)

	// Get all and modify.
	statuses := tracker.GetAll()
	statuses["clamav"].Status = StatusFailed

	// Original should not be modified.
	status := tracker.Get("clamav")
	if status.Status != StatusIdle {
		t.Errorf("Status = %q, want %q (should not be modified)", status.Status, StatusIdle)
	}
}

func TestStatus_Constants(t *testing.T) {
	t.Parallel()

	// Verify status constants are defined.
	if StatusPending == "" {
		t.Error("StatusPending should not be empty")
	}
	if StatusIdle == "" {
		t.Error("StatusIdle should not be empty")
	}
	if StatusUpdating == "" {
		t.Error("StatusUpdating should not be empty")
	}
	if StatusFailed == "" {
		t.Error("StatusFailed should not be empty")
	}

	// Verify they're distinct.
	statuses := []Status{StatusPending, StatusIdle, StatusUpdating, StatusFailed}
	seen := make(map[Status]bool)
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("Duplicate status constant: %q", s)
		}
		seen[s] = true
	}
}
