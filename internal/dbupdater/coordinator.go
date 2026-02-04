// ABOUTME: Scan coordinator with RWLock semantics for scan/update coordination
// ABOUTME: Multiple scans concurrent, updates exclusive with context support

package dbupdater

import (
	"context"
	"sync"
	"sync/atomic"
)

// CoordinatorStatus represents the current state of the coordinator.
type CoordinatorStatus struct {
	// ActiveScans is the number of scans currently in progress.
	ActiveScans int

	// UpdateInProgress indicates if a database update is running.
	UpdateInProgress bool
}

// ScanCoordinator manages concurrent access between scans and database updates.
// It implements RWLock semantics: multiple scans can run concurrently,
// but updates are exclusive (no scans during update, no updates during scan).
type ScanCoordinator struct {
	mu sync.Mutex

	// Condition variable for waiting.
	cond *sync.Cond

	// activeScans tracks the number of active scan operations.
	activeScans int32

	// updating indicates if an update operation is in progress.
	updating atomic.Bool
}

// NewScanCoordinator creates a new scan coordinator.
func NewScanCoordinator() *ScanCoordinator {
	c := &ScanCoordinator{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// AcquireForScan acquires the lock for a scan operation.
// Multiple scans can run concurrently. Blocks if an update is in progress.
// Returns a release function that must be called when the scan completes.
func (c *ScanCoordinator) AcquireForScan(ctx context.Context) (release func(), err error) {
	// Check context first.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()

	// Wait while update is in progress.
	for c.updating.Load() {
		// Check context in wait loop.
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return nil, err
		}

		// Use a goroutine to handle context cancellation during wait.
		done := make(chan struct{})
		go func() {
			<-ctx.Done()
			c.cond.Broadcast()
		}()

		c.cond.Wait()
		close(done)

		// Check context again after waking up.
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return nil, err
		}
	}

	// Increment active scans.
	atomic.AddInt32(&c.activeScans, 1)
	c.mu.Unlock()

	// Return release function with once guard.
	var once sync.Once
	return func() {
		once.Do(func() {
			newCount := atomic.AddInt32(&c.activeScans, -1)
			if newCount == 0 {
				c.cond.Broadcast()
			}
		})
	}, nil
}

// AcquireForUpdate acquires the lock for an update operation.
// Updates are exclusive: waits for all scans to complete and blocks new scans.
// Returns a release function that must be called when the update completes.
func (c *ScanCoordinator) AcquireForUpdate(ctx context.Context) (release func(), err error) {
	// Check context first.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()

	// Wait while another update is in progress or scans are active.
	for c.updating.Load() || atomic.LoadInt32(&c.activeScans) > 0 {
		// Check context in wait loop.
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return nil, err
		}

		// Use a goroutine to handle context cancellation during wait.
		go func() {
			<-ctx.Done()
			c.cond.Broadcast()
		}()

		c.cond.Wait()

		// Check context again after waking up.
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return nil, err
		}
	}

	// Mark update as in progress.
	c.updating.Store(true)
	c.mu.Unlock()

	// Return release function with once guard.
	var once sync.Once
	return func() {
		once.Do(func() {
			c.updating.Store(false)
			c.cond.Broadcast()
		})
	}, nil
}

// HasActiveScans returns true if there are any active scan operations.
func (c *ScanCoordinator) HasActiveScans() bool {
	return atomic.LoadInt32(&c.activeScans) > 0
}

// IsUpdating returns true if an update operation is in progress.
func (c *ScanCoordinator) IsUpdating() bool {
	return c.updating.Load()
}

// Status returns the current coordinator status.
func (c *ScanCoordinator) Status() CoordinatorStatus {
	return CoordinatorStatus{
		ActiveScans:      int(atomic.LoadInt32(&c.activeScans)),
		UpdateInProgress: c.updating.Load(),
	}
}
