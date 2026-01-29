// ABOUTME: Unit tests for Redis state manager with job status tracking
// ABOUTME: Tests hash-based state storage, TTL, and atomic updates

package redis

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestNewStateManager(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	cfg := StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: time.Hour,
	}

	mgr := NewStateManager(client, cfg)
	if mgr == nil {
		t.Error("NewStateManager() returned nil")
	}
}

func TestStateManager_SetGetField(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "argus:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	mgr := NewStateManager(client, StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: time.Hour,
	})

	ctx := context.Background()
	jobID := "test-job-123"

	// Set a field.
	if err := mgr.SetField(ctx, jobID, "trivy_status", "running"); err != nil {
		t.Fatalf("SetField() error = %v", err)
	}

	// Get the field.
	val, err := mgr.GetField(ctx, jobID, "trivy_status")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "running" {
		t.Errorf("GetField() = %q, want %q", val, "running")
	}

	// Verify the key has the correct prefix in Redis.
	expectedKey := "argus:job_state:test-job-123"
	if !mr.Exists(expectedKey) {
		t.Errorf("key %q not found in Redis", expectedKey)
	}
}

func TestStateManager_SetGetJSON(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "prod:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	mgr := NewStateManager(client, StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: time.Hour,
	})

	ctx := context.Background()
	jobID := "job-456"

	// Set a JSON value.
	status := map[string]string{
		"trivy":  "completed",
		"clamav": "running",
	}
	if err := mgr.SetJSON(ctx, jobID, "argus_status", status); err != nil {
		t.Fatalf("SetJSON() error = %v", err)
	}

	// Get the JSON value.
	var got map[string]string
	if err := mgr.GetJSON(ctx, jobID, "argus_status", &got); err != nil {
		t.Fatalf("GetJSON() error = %v", err)
	}

	if got["trivy"] != "completed" || got["clamav"] != "running" {
		t.Errorf("GetJSON() = %v, want %v", got, status)
	}
}

func TestStateManager_SetMultipleFields(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	mgr := NewStateManager(client, StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: time.Hour,
	})

	ctx := context.Background()
	jobID := "multi-field-job"

	// Set multiple fields at once.
	fields := map[string]string{
		"trivy_status":  "completed",
		"clamav_status": "running",
		"started_at":    "2026-01-29T12:00:00Z",
	}
	if err := mgr.SetFields(ctx, jobID, fields); err != nil {
		t.Fatalf("SetFields() error = %v", err)
	}

	// Verify all fields.
	for k, want := range fields {
		got, err := mgr.GetField(ctx, jobID, k)
		if err != nil {
			t.Errorf("GetField(%q) error = %v", k, err)
			continue
		}
		if got != want {
			t.Errorf("GetField(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestStateManager_GetAllFields(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	mgr := NewStateManager(client, StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: time.Hour,
	})

	ctx := context.Background()
	jobID := "all-fields-job"

	// Set multiple fields.
	fields := map[string]string{
		"status":     "completed",
		"error":      "",
		"started_at": "2026-01-29T12:00:00Z",
	}
	if err := mgr.SetFields(ctx, jobID, fields); err != nil {
		t.Fatalf("SetFields() error = %v", err)
	}

	// Get all fields.
	got, err := mgr.GetAllFields(ctx, jobID)
	if err != nil {
		t.Fatalf("GetAllFields() error = %v", err)
	}

	for k, want := range fields {
		if got[k] != want {
			t.Errorf("GetAllFields()[%q] = %q, want %q", k, got[k], want)
		}
	}
}

func TestStateManager_SetTTL(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	mgr := NewStateManager(client, StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: time.Hour,
	})

	ctx := context.Background()
	jobID := "ttl-job"

	// Set a field.
	if err := mgr.SetField(ctx, jobID, "status", "pending"); err != nil {
		t.Fatalf("SetField() error = %v", err)
	}

	// Set custom TTL.
	if err := mgr.SetTTL(ctx, jobID, 24*time.Hour); err != nil {
		t.Fatalf("SetTTL() error = %v", err)
	}

	// Verify TTL was set.
	key := "test:job_state:ttl-job"
	ttl := mr.TTL(key)
	if ttl <= 0 {
		t.Errorf("TTL not set on key %q", key)
	}
}

func TestStateManager_Delete(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	mgr := NewStateManager(client, StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: time.Hour,
	})

	ctx := context.Background()
	jobID := "delete-job"

	// Set a field.
	if err := mgr.SetField(ctx, jobID, "status", "pending"); err != nil {
		t.Fatalf("SetField() error = %v", err)
	}

	// Verify it exists.
	key := "test:job_state:delete-job"
	if !mr.Exists(key) {
		t.Fatalf("key %q should exist", key)
	}

	// Delete.
	if err := mgr.Delete(ctx, jobID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's gone.
	if mr.Exists(key) {
		t.Errorf("key %q should not exist after Delete()", key)
	}
}

func TestStateManager_JobKey(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "prod:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	mgr := NewStateManager(client, StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: time.Hour,
	})

	// Verify key composition.
	got := mgr.JobKey("abc-123")
	want := "prod:job_state:abc-123"
	if got != want {
		t.Errorf("JobKey() = %q, want %q", got, want)
	}
}

func TestStateManager_GetFieldNotFound(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	mgr := NewStateManager(client, StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: time.Hour,
	})

	ctx := context.Background()

	// Get non-existent field.
	val, err := mgr.GetField(ctx, "nonexistent", "field")
	if err == nil {
		t.Error("GetField() expected error for non-existent field")
	}
	if val != "" {
		t.Errorf("GetField() = %q, want empty string", val)
	}
}

// TestStateManager_InitState tests initializing a new job state.
func TestStateManager_InitState(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "argus:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	mgr := NewStateManager(client, StateManagerConfig{
		KeyPrefix: "job_state:",
		DefaultTTL: 7 * 24 * time.Hour, // 7 days
	})

	ctx := context.Background()
	jobID := "init-job"

	// Initialize state with pending status.
	status := map[string]string{
		"trivy":  "pending",
		"clamav": "pending",
	}
	statusJSON, _ := json.Marshal(status)

	initial := map[string]string{
		"argus_status": string(statusJSON),
		"started_at":   time.Now().UTC().Format(time.RFC3339),
	}

	if err := mgr.InitState(ctx, jobID, initial); err != nil {
		t.Fatalf("InitState() error = %v", err)
	}

	// Verify fields.
	got, err := mgr.GetField(ctx, jobID, "argus_status")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if got != string(statusJSON) {
		t.Errorf("argus_status = %q, want %q", got, string(statusJSON))
	}

	// Verify TTL was set.
	key := "argus:job_state:init-job"
	ttl := mr.TTL(key)
	if ttl <= 0 {
		t.Errorf("TTL not set on key %q", key)
	}
}
