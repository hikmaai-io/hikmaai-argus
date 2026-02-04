// ABOUTME: Tests for updater interface types and result structures
// ABOUTME: Validates update results, error handling, and interface compliance

package dbupdater

import (
	"testing"
	"time"
)

func TestUpdateResult_Success(t *testing.T) {
	t.Parallel()

	result := &UpdateResult{
		Success:    true,
		Downloaded: 2,
		Skipped:    1,
		Failed:     0,
		Duration:   5 * time.Second,
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if result.Downloaded != 2 {
		t.Errorf("Downloaded = %d, want 2", result.Downloaded)
	}
	if result.HasErrors() {
		t.Error("HasErrors() should be false for successful result")
	}
}

func TestUpdateResult_HasErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result UpdateResult
		want   bool
	}{
		{
			name: "no errors",
			result: UpdateResult{
				Success:    true,
				Downloaded: 1,
				Failed:     0,
			},
			want: false,
		},
		{
			name: "has failed count",
			result: UpdateResult{
				Success:    false,
				Downloaded: 1,
				Failed:     1,
			},
			want: true,
		},
		{
			name: "has error message",
			result: UpdateResult{
				Success: false,
				Error:   "connection refused",
			},
			want: true,
		},
		{
			name: "both failed and error",
			result: UpdateResult{
				Success: false,
				Failed:  1,
				Error:   "timeout",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.result.HasErrors(); got != tt.want {
				t.Errorf("HasErrors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdateResult_String(t *testing.T) {
	t.Parallel()

	result := &UpdateResult{
		Success:    true,
		Downloaded: 2,
		Skipped:    1,
		Failed:     0,
		Duration:   3 * time.Second,
	}

	str := result.String()

	// Should contain key information.
	if str == "" {
		t.Error("String() should not be empty")
	}
}

func TestVersionInfo_String(t *testing.T) {
	t.Parallel()

	info := VersionInfo{
		Version:   12345,
		BuildTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		DBFiles: map[string]int{
			"main.cvd":  12345,
			"daily.cvd": 67890,
		},
	}

	str := info.String()
	if str == "" {
		t.Error("String() should not be empty")
	}
}

func TestCheckResult_NeedsUpdate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result CheckResult
		want   bool
	}{
		{
			name: "update available",
			result: CheckResult{
				UpdateAvailable: true,
			},
			want: true,
		},
		{
			name: "no update",
			result: CheckResult{
				UpdateAvailable: false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.result.NeedsUpdate(); got != tt.want {
				t.Errorf("NeedsUpdate() = %v, want %v", got, tt.want)
			}
		})
	}
}
