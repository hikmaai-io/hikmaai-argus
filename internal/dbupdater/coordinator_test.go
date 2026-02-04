// ABOUTME: Tests for scan coordinator with RWLock semantics
// ABOUTME: Validates concurrent scan access and exclusive update locking

package dbupdater

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanCoordinator_AcquireForScan_Success(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()

	ctx := context.Background()
	release, err := c.AcquireForScan(ctx)
	if err != nil {
		t.Fatalf("AcquireForScan() error = %v", err)
	}
	defer release()

	// Should have acquired the lock.
	if !c.HasActiveScans() {
		t.Error("Expected active scans after acquire")
	}
}

func TestScanCoordinator_AcquireForScan_Release(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()

	ctx := context.Background()
	release, err := c.AcquireForScan(ctx)
	if err != nil {
		t.Fatalf("AcquireForScan() error = %v", err)
	}

	// Release.
	release()

	// Should have no active scans.
	if c.HasActiveScans() {
		t.Error("Expected no active scans after release")
	}
}

func TestScanCoordinator_AcquireForScan_ConcurrentAllowed(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()
	ctx := context.Background()

	var acquired atomic.Int32
	var wg sync.WaitGroup

	// Start multiple concurrent scans.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			release, err := c.AcquireForScan(ctx)
			if err != nil {
				return
			}
			acquired.Add(1)

			// Hold the lock briefly.
			time.Sleep(50 * time.Millisecond)

			acquired.Add(-1)
			release()
		}()
	}

	// Wait a bit for all to acquire.
	time.Sleep(20 * time.Millisecond)

	// All should be acquired concurrently.
	if acquired.Load() < 3 {
		t.Errorf("Expected at least 3 concurrent acquisitions, got %d", acquired.Load())
	}

	wg.Wait()
}

func TestScanCoordinator_AcquireForUpdate_Success(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()

	ctx := context.Background()
	release, err := c.AcquireForUpdate(ctx)
	if err != nil {
		t.Fatalf("AcquireForUpdate() error = %v", err)
	}
	defer release()

	// Should be in update mode.
	if !c.IsUpdating() {
		t.Error("Expected IsUpdating() to be true")
	}
}

func TestScanCoordinator_AcquireForUpdate_BlocksScans(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()
	ctx := context.Background()

	// Acquire update lock.
	releaseUpdate, err := c.AcquireForUpdate(ctx)
	if err != nil {
		t.Fatalf("AcquireForUpdate() error = %v", err)
	}

	// Try to acquire scan with timeout.
	scanCtx, scanCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer scanCancel()

	_, err = c.AcquireForScan(scanCtx)
	if err == nil {
		t.Error("AcquireForScan() should fail while update is in progress")
	}

	// Release update lock.
	releaseUpdate()

	// Now scan should work.
	release, err := c.AcquireForScan(ctx)
	if err != nil {
		t.Errorf("AcquireForScan() after update release: error = %v", err)
	}
	release()
}

func TestScanCoordinator_AcquireForUpdate_WaitsForScans(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()
	ctx := context.Background()

	// Start a scan.
	releaseScan, err := c.AcquireForScan(ctx)
	if err != nil {
		t.Fatalf("AcquireForScan() error = %v", err)
	}

	// Try to acquire update with short timeout.
	updateCtx, updateCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer updateCancel()

	_, err = c.AcquireForUpdate(updateCtx)
	if err == nil {
		t.Error("AcquireForUpdate() should fail while scan is in progress")
	}

	// Release scan.
	releaseScan()

	// Now update should work.
	release, err := c.AcquireForUpdate(ctx)
	if err != nil {
		t.Errorf("AcquireForUpdate() after scan release: error = %v", err)
	}
	release()
}

func TestScanCoordinator_AcquireForScan_ContextCancelled(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()

	// Hold an update lock.
	ctx := context.Background()
	releaseUpdate, _ := c.AcquireForUpdate(ctx)

	// Cancel context before trying to acquire scan.
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()

	_, err := c.AcquireForScan(cancelledCtx)
	if err == nil {
		t.Error("AcquireForScan() should fail with cancelled context")
	}

	releaseUpdate()
}

func TestScanCoordinator_AcquireForUpdate_ContextCancelled(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()

	// Hold a scan lock.
	ctx := context.Background()
	releaseScan, _ := c.AcquireForScan(ctx)

	// Cancel context before trying to acquire update.
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()

	_, err := c.AcquireForUpdate(cancelledCtx)
	if err == nil {
		t.Error("AcquireForUpdate() should fail with cancelled context")
	}

	releaseScan()
}

func TestScanCoordinator_Status(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()
	ctx := context.Background()

	status := c.Status()
	if status.ActiveScans != 0 {
		t.Errorf("Initial ActiveScans = %d, want 0", status.ActiveScans)
	}
	if status.UpdateInProgress {
		t.Error("Initial UpdateInProgress should be false")
	}

	// Acquire scan.
	release, _ := c.AcquireForScan(ctx)
	status = c.Status()
	if status.ActiveScans != 1 {
		t.Errorf("After scan: ActiveScans = %d, want 1", status.ActiveScans)
	}
	release()

	// Acquire update.
	releaseUpdate, _ := c.AcquireForUpdate(ctx)
	status = c.Status()
	if !status.UpdateInProgress {
		t.Error("After update: UpdateInProgress should be true")
	}
	releaseUpdate()
}

func TestScanCoordinator_DoubleRelease_Safe(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()
	ctx := context.Background()

	release, _ := c.AcquireForScan(ctx)

	// Double release should not panic.
	release()
	release()

	// Should still work after double release.
	release2, err := c.AcquireForScan(ctx)
	if err != nil {
		t.Errorf("AcquireForScan() after double release: error = %v", err)
	}
	release2()
}

func TestScanCoordinator_UpdateExclusive(t *testing.T) {
	t.Parallel()

	c := NewScanCoordinator()
	ctx := context.Background()

	// Acquire first update.
	releaseFirst, err := c.AcquireForUpdate(ctx)
	if err != nil {
		t.Fatalf("First AcquireForUpdate() error = %v", err)
	}

	// Second update should block/fail with timeout.
	secondCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	_, err = c.AcquireForUpdate(secondCtx)
	if err == nil {
		t.Error("Second AcquireForUpdate() should fail while first is held")
	}

	releaseFirst()
}
