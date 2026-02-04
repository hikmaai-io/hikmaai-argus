// ABOUTME: Tests for DB update service orchestration
// ABOUTME: Validates lifecycle, scheduling, retry logic, and manual triggers

package dbupdater

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// mockUpdater is a test implementation of the Updater interface.
type mockUpdater struct {
	name           string
	updateCount    atomic.Int32
	checkCount     atomic.Int32
	shouldFail     bool
	updateDelay    time.Duration
	ready          bool
	versionInfo    VersionInfo
	updateCallback func()
}

func newMockUpdater(name string) *mockUpdater {
	return &mockUpdater{
		name:  name,
		ready: true,
	}
}

func (m *mockUpdater) Name() string { return m.name }

func (m *mockUpdater) Update(ctx context.Context) (*UpdateResult, error) {
	if m.updateDelay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.updateDelay):
		}
	}

	m.updateCount.Add(1)

	if m.updateCallback != nil {
		m.updateCallback()
	}

	if m.shouldFail {
		return &UpdateResult{
			Success: false,
			Failed:  1,
			Error:   "mock failure",
		}, errors.New("mock failure")
	}

	return &UpdateResult{
		Success:    true,
		Downloaded: 1,
	}, nil
}

func (m *mockUpdater) CheckForUpdates(ctx context.Context) (*CheckResult, error) {
	m.checkCount.Add(1)

	if m.shouldFail {
		return nil, errors.New("mock check failure")
	}

	return &CheckResult{
		UpdateAvailable: true,
	}, nil
}

func (m *mockUpdater) GetVersionInfo() VersionInfo { return m.versionInfo }
func (m *mockUpdater) IsReady() bool               { return m.ready }

func TestDBUpdateService_NewService(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator: NewScanCoordinator(),
	})

	if svc == nil {
		t.Fatal("NewDBUpdateService() returned nil")
	}
}

func TestDBUpdateService_RegisterUpdater(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator: NewScanCoordinator(),
	})

	mock := newMockUpdater("test")
	svc.RegisterUpdater(mock, 1*time.Hour)

	statuses := svc.GetStatus()
	if len(statuses) != 1 {
		t.Errorf("GetStatus() returned %d statuses, want 1", len(statuses))
	}

	if statuses["test"] == nil {
		t.Error("Status for 'test' updater not found")
	}
}

func TestDBUpdateService_StartStop(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator: NewScanCoordinator(),
	})

	mock := newMockUpdater("test")
	svc.RegisterUpdater(mock, 1*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start service.
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Should be running.
	if !svc.IsRunning() {
		t.Error("IsRunning() should be true after Start()")
	}

	// Stop service.
	svc.Stop()

	// Give it time to stop.
	time.Sleep(50 * time.Millisecond)

	if svc.IsRunning() {
		t.Error("IsRunning() should be false after Stop()")
	}
}

func TestDBUpdateService_InitialUpdate(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator:      NewScanCoordinator(),
		RunInitialUpdate: true,
	})

	mock := newMockUpdater("test")
	svc.RegisterUpdater(mock, 1*time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for initial update.
	time.Sleep(100 * time.Millisecond)

	svc.Stop()

	// Initial update should have been triggered.
	if mock.updateCount.Load() < 1 {
		t.Error("Initial update was not triggered")
	}
}

func TestDBUpdateService_PeriodicUpdate(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator: NewScanCoordinator(),
	})

	mock := newMockUpdater("test")
	svc.RegisterUpdater(mock, 50*time.Millisecond) // Very short interval for testing.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for at least 2 intervals.
	time.Sleep(150 * time.Millisecond)

	svc.Stop()

	// Should have multiple updates.
	if mock.updateCount.Load() < 2 {
		t.Errorf("Expected at least 2 updates, got %d", mock.updateCount.Load())
	}
}

func TestDBUpdateService_TriggerUpdate(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator: NewScanCoordinator(),
	})

	mock := newMockUpdater("test")
	svc.RegisterUpdater(mock, 1*time.Hour) // Long interval.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Manually trigger update.
	if err := svc.TriggerUpdate(ctx, "test"); err != nil {
		t.Errorf("TriggerUpdate() error = %v", err)
	}

	// Wait for update to process.
	time.Sleep(100 * time.Millisecond)

	svc.Stop()

	if mock.updateCount.Load() < 1 {
		t.Error("Manual trigger did not execute update")
	}
}

func TestDBUpdateService_TriggerUpdate_NotFound(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator: NewScanCoordinator(),
	})

	ctx := context.Background()

	err := svc.TriggerUpdate(ctx, "nonexistent")
	if err == nil {
		t.Error("TriggerUpdate() should error for nonexistent updater")
	}
}

func TestDBUpdateService_RetryOnFailure(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator: NewScanCoordinator(),
		RetryConfig: BackoffConfig{
			MaxRetries:     3,
			InitialDelay:   10 * time.Millisecond,
			MaxDelay:       50 * time.Millisecond,
			Multiplier:     2.0,
			JitterFraction: 0,
		},
	})

	mock := newMockUpdater("test")
	mock.shouldFail = true
	svc.RegisterUpdater(mock, 1*time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Trigger update (which will fail and retry).
	_ = svc.TriggerUpdate(ctx, "test")

	// Wait for retries.
	time.Sleep(200 * time.Millisecond)

	svc.Stop()

	// Should have retried multiple times.
	count := mock.updateCount.Load()
	if count < 2 {
		t.Errorf("Expected retry attempts, got %d updates", count)
	}
}

func TestDBUpdateService_CoordinatesWithScans(t *testing.T) {
	t.Parallel()

	coordinator := NewScanCoordinator()
	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator:      coordinator,
		RunInitialUpdate: true,
	})

	updateStarted := make(chan struct{}, 1)
	updateDone := make(chan struct{})
	mock := newMockUpdater("test")
	mock.updateDelay = 200 * time.Millisecond
	mock.updateCallback = func() {
		select {
		case updateStarted <- struct{}{}:
		default:
		}
		<-updateDone // Wait until test is done checking.
	}
	svc.RegisterUpdater(mock, 1*time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start service (triggers initial update).
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for update to start.
	select {
	case <-updateStarted:
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for update to start")
	}

	// Update is in progress; coordinator should block scans.
	scanCtx, scanCancel := context.WithTimeout(ctx, 50*time.Millisecond)
	_, err := coordinator.AcquireForScan(scanCtx)
	scanCancel()

	// Allow update to finish.
	close(updateDone)
	svc.Stop()

	if err == nil {
		t.Error("AcquireForScan() should block/timeout while update is in progress")
	}
}

func TestDBUpdateService_GetStatus(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator: NewScanCoordinator(),
	})

	mock := newMockUpdater("test")
	mock.versionInfo = VersionInfo{Version: 123}
	svc.RegisterUpdater(mock, 1*time.Hour)

	statuses := svc.GetStatus()

	if len(statuses) != 1 {
		t.Errorf("GetStatus() returned %d statuses, want 1", len(statuses))
	}

	status := statuses["test"]
	if status == nil {
		t.Fatal("Status for 'test' not found")
	}

	if status.Name != "test" {
		t.Errorf("Status.Name = %q, want %q", status.Name, "test")
	}
}

func TestDBUpdateService_MultipleUpdaters(t *testing.T) {
	t.Parallel()

	svc := NewDBUpdateService(DBUpdateServiceConfig{
		Coordinator:      NewScanCoordinator(),
		RunInitialUpdate: true,
	})

	clamav := newMockUpdater("clamav")
	trivy := newMockUpdater("trivy")

	svc.RegisterUpdater(clamav, 100*time.Millisecond)
	svc.RegisterUpdater(trivy, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for updates.
	time.Sleep(150 * time.Millisecond)

	svc.Stop()

	// Both should have been updated.
	if clamav.updateCount.Load() < 1 {
		t.Error("ClamAV updater was not called")
	}
	if trivy.updateCount.Load() < 1 {
		t.Error("Trivy updater was not called")
	}

	// Both should be in status.
	statuses := svc.GetStatus()
	if len(statuses) != 2 {
		t.Errorf("GetStatus() returned %d statuses, want 2", len(statuses))
	}
}
