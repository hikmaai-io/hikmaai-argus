// ABOUTME: Tests for audit logging system
// ABOUTME: Validates security event logging and structured audit trails

package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestNewAuditLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	al := NewAuditLogger(logger)

	if al == nil {
		t.Fatal("NewAuditLogger() returned nil")
	}
}

func TestAuditLogger_LogScanRequest(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	al := NewAuditLogger(logger)

	ctx := WithCorrelationID(context.Background(), "test-correlation-id")
	al.LogScanRequest(ctx, "org-123", "job-456", "abc123def456")

	// Verify JSON output.
	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if result["event_type"] != "SCAN" {
		t.Errorf("event_type = %v, want SCAN", result["event_type"])
	}
	if result["action"] != "CREATE" {
		t.Errorf("action = %v, want CREATE", result["action"])
	}
	if result["organization_id"] != "org-123" {
		t.Errorf("organization_id = %v, want org-123", result["organization_id"])
	}
}

func TestAuditLogger_LogAccessDenied(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	al := NewAuditLogger(logger)

	ctx := context.Background()
	al.LogAccessDenied(ctx, "org-123", "/api/v1/files/abc", "unauthorized")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if result["event_type"] != "ACCESS" {
		t.Errorf("event_type = %v, want ACCESS", result["event_type"])
	}
	if result["result"] != "denied" {
		t.Errorf("result = %v, want denied", result["result"])
	}
}

func TestAuditLogger_LogDBUpdate(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	al := NewAuditLogger(logger)

	ctx := context.Background()
	al.LogDBUpdate(ctx, "clamav", true, "downloaded 3 files")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if result["event_type"] != "UPDATE" {
		t.Errorf("event_type = %v, want UPDATE", result["event_type"])
	}
	if result["result"] != "success" {
		t.Errorf("result = %v, want success", result["result"])
	}
}

func TestAuditLogger_LogJobCancellation(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	al := NewAuditLogger(logger)

	ctx := context.Background()
	al.LogJobCancellation(ctx, "job-789", "user_request")

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if result["event_type"] != "SCAN" {
		t.Errorf("event_type = %v, want SCAN", result["event_type"])
	}
	if result["action"] != "DELETE" {
		t.Errorf("action = %v, want DELETE", result["action"])
	}
}

func TestAuditEvent_Constants(t *testing.T) {
	t.Parallel()

	if EventTypeScan != "SCAN" {
		t.Errorf("EventTypeScan = %q, want SCAN", EventTypeScan)
	}
	if EventTypeAccess != "ACCESS" {
		t.Errorf("EventTypeAccess = %q, want ACCESS", EventTypeAccess)
	}
	if EventTypeUpdate != "UPDATE" {
		t.Errorf("EventTypeUpdate = %q, want UPDATE", EventTypeUpdate)
	}
}
