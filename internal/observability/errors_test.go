// ABOUTME: Tests for structured error context system
// ABOUTME: Validates error codes, categories, stack traces, and slog integration

package observability

import (
	"errors"
	"log/slog"
	"testing"
)

func TestNewErrorContext(t *testing.T) {
	t.Parallel()

	ec := NewErrorContext("SCAN_TIMEOUT", "transient", "clamav_scan")

	if ec.Code != "SCAN_TIMEOUT" {
		t.Errorf("Code = %q, want %q", ec.Code, "SCAN_TIMEOUT")
	}
	if ec.Category != "transient" {
		t.Errorf("Category = %q, want %q", ec.Category, "transient")
	}
	if ec.Operation != "clamav_scan" {
		t.Errorf("Operation = %q, want %q", ec.Operation, "clamav_scan")
	}
}

func TestErrorContext_WithStack(t *testing.T) {
	t.Parallel()

	ec := NewErrorContext("TEST_ERROR", "permanent", "test_op").WithStack()

	if ec.StackTrace == "" {
		t.Error("WithStack() should populate StackTrace")
	}
}

func TestErrorContext_WithDetails(t *testing.T) {
	t.Parallel()

	details := map[string]any{
		"file_size": 1024,
		"timeout":   "30s",
	}
	ec := NewErrorContext("TEST_ERROR", "transient", "test_op").WithDetails(details)

	if ec.Details == nil {
		t.Fatal("WithDetails() should populate Details")
	}
	if ec.Details.(map[string]any)["file_size"] != 1024 {
		t.Error("Details should contain file_size")
	}
}

func TestErrorContext_WithError(t *testing.T) {
	t.Parallel()

	err := errors.New("underlying error")
	ec := NewErrorContext("TEST_ERROR", "transient", "test_op").WithError(err)

	if ec.Err != err {
		t.Error("WithError() should store the error")
	}
}

func TestErrorContext_IsRetryable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		category    string
		wantRetry   bool
	}{
		{"transient", true},
		{"permanent", false},
		{"user_error", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			ec := NewErrorContext("TEST", tt.category, "op")
			if ec.IsRetryable() != tt.wantRetry {
				t.Errorf("IsRetryable() = %v, want %v", ec.IsRetryable(), tt.wantRetry)
			}
		})
	}
}

func TestErrorContext_LogValue(t *testing.T) {
	t.Parallel()

	ec := NewErrorContext("SCAN_FAILED", "transient", "clamav_scan").
		WithDetails(map[string]any{"size": 100})

	// LogValue should return a slog.Value that can be used in logging.
	val := ec.LogValue()

	if val.Kind() != slog.KindGroup {
		t.Errorf("LogValue() kind = %v, want Group", val.Kind())
	}
}

func TestErrorContext_Error(t *testing.T) {
	t.Parallel()

	ec := NewErrorContext("SCAN_TIMEOUT", "transient", "clamav_scan")
	errStr := ec.Error()

	if errStr == "" {
		t.Error("Error() should return non-empty string")
	}
}

func TestErrorCategory_Constants(t *testing.T) {
	t.Parallel()

	if CategoryTransient != "transient" {
		t.Errorf("CategoryTransient = %q, want %q", CategoryTransient, "transient")
	}
	if CategoryPermanent != "permanent" {
		t.Errorf("CategoryPermanent = %q, want %q", CategoryPermanent, "permanent")
	}
	if CategoryUserError != "user_error" {
		t.Errorf("CategoryUserError = %q, want %q", CategoryUserError, "user_error")
	}
}
