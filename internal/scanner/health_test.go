// ABOUTME: Tests for scanner health check system
// ABOUTME: Validates binary verification, failure tracking, and health queries

package scanner

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthChecker_NewHealthChecker(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{})

	if hc == nil {
		t.Fatal("NewHealthChecker() returned nil")
	}
}

func TestHealthChecker_Register(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{})

	hc.Register("clamav", func(ctx context.Context) error {
		return nil
	})

	if !hc.IsRegistered("clamav") {
		t.Error("IsRegistered(clamav) should be true")
	}
	if hc.IsRegistered("nonexistent") {
		t.Error("IsRegistered(nonexistent) should be false")
	}
}

func TestHealthChecker_IsHealthy_NotRegistered(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{})

	if hc.IsHealthy("nonexistent") {
		t.Error("IsHealthy(nonexistent) should be false")
	}
}

func TestHealthChecker_CheckHealth_Success(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{})

	hc.Register("clamav", func(ctx context.Context) error {
		return nil
	})

	ctx := context.Background()
	err := hc.CheckHealth(ctx, "clamav")

	if err != nil {
		t.Errorf("CheckHealth() error = %v", err)
	}
	if !hc.IsHealthy("clamav") {
		t.Error("IsHealthy(clamav) should be true after successful check")
	}
}

func TestHealthChecker_CheckHealth_Failure(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{
		UnhealthyThreshold: 1, // Mark unhealthy after first failure.
	})

	hc.Register("clamav", func(ctx context.Context) error {
		return errors.New("version check failed")
	})

	ctx := context.Background()
	err := hc.CheckHealth(ctx, "clamav")

	if err == nil {
		t.Error("CheckHealth() should return error on failure")
	}
	if hc.IsHealthy("clamav") {
		t.Error("IsHealthy(clamav) should be false after failed check")
	}
}

func TestHealthChecker_ConsecutiveFailures(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{
		UnhealthyThreshold: 3,
	})

	failureCount := 0
	hc.Register("clamav", func(ctx context.Context) error {
		failureCount++
		if failureCount <= 3 {
			return errors.New("failure")
		}
		return nil
	})

	ctx := context.Background()

	// First two failures should not mark as unhealthy.
	for i := 0; i < 2; i++ {
		_ = hc.CheckHealth(ctx, "clamav")
	}

	status := hc.GetStatus("clamav")
	if status.ConsecutiveFailures != 2 {
		t.Errorf("ConsecutiveFailures = %d, want 2", status.ConsecutiveFailures)
	}

	// Third failure should mark as unhealthy.
	_ = hc.CheckHealth(ctx, "clamav")

	if hc.IsHealthy("clamav") {
		t.Error("IsHealthy(clamav) should be false after threshold failures")
	}

	// Success should reset.
	_ = hc.CheckHealth(ctx, "clamav")

	if !hc.IsHealthy("clamav") {
		t.Error("IsHealthy(clamav) should be true after success")
	}

	status = hc.GetStatus("clamav")
	if status.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0 after success", status.ConsecutiveFailures)
	}
}

func TestHealthChecker_GetStatus(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{})

	hc.Register("clamav", func(ctx context.Context) error {
		return nil
	})

	ctx := context.Background()
	_ = hc.CheckHealth(ctx, "clamav")

	status := hc.GetStatus("clamav")

	if status == nil {
		t.Fatal("GetStatus() returned nil")
	}
	if status.Name != "clamav" {
		t.Errorf("Status.Name = %q, want %q", status.Name, "clamav")
	}
	if status.TotalChecks != 1 {
		t.Errorf("Status.TotalChecks = %d, want 1", status.TotalChecks)
	}
	if status.LastCheckTime.IsZero() {
		t.Error("Status.LastCheckTime should not be zero")
	}
}

func TestHealthChecker_GetAllStatuses(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{})

	hc.Register("clamav", func(ctx context.Context) error { return nil })
	hc.Register("trivy", func(ctx context.Context) error { return nil })

	statuses := hc.GetAllStatuses()

	if len(statuses) != 2 {
		t.Errorf("GetAllStatuses() returned %d statuses, want 2", len(statuses))
	}
}

func TestHealthChecker_StartStop(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{
		CheckInterval: 50 * time.Millisecond,
	})

	var checkCount atomic.Int32
	hc.Register("clamav", func(ctx context.Context) error {
		checkCount.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start periodic checks.
	hc.Start(ctx)

	// Wait for some checks.
	time.Sleep(150 * time.Millisecond)

	hc.Stop()

	count := checkCount.Load()
	if count < 2 {
		t.Errorf("Expected at least 2 checks, got %d", count)
	}
}

func TestHealthChecker_ContextCancellation(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{})

	hc.Register("slow", func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			return nil
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := hc.CheckHealth(ctx, "slow")
	if err == nil {
		t.Error("CheckHealth() should error on context cancellation")
	}
}

func TestHealthChecker_ResponseTime(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(HealthCheckerConfig{})

	hc.Register("clamav", func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		return nil
	})

	ctx := context.Background()
	_ = hc.CheckHealth(ctx, "clamav")

	status := hc.GetStatus("clamav")

	if status.AvgResponseTime < 10*time.Millisecond {
		t.Errorf("AvgResponseTime = %v, expected >= 10ms", status.AvgResponseTime)
	}
}

func TestHealthStatus_String(t *testing.T) {
	t.Parallel()

	status := &HealthStatus{
		Name:    "clamav",
		Healthy: true,
	}

	str := status.String()
	if str == "" {
		t.Error("String() should not be empty")
	}
}
