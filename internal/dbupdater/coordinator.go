// ABOUTME: Scan coordinator with RWLock semantics for scan/update coordination
// ABOUTME: Multiple scans concurrent, updates exclusive with context support

package dbupdater

import (
	"context"
	"sync"
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
//
// Uses channel-based signaling for context-aware waiting without goroutine leaks.
type ScanCoordinator struct {
	mu sync.Mutex

	// activeScans tracks the number of active scan operations.
	activeScans int32

	// updating indicates if an update operation is in progress.
	updating bool

	// broadcast is closed to wake all waiters, then recreated.
	broadcast chan struct{}
}

// NewScanCoordinator creates a new scan coordinator.
func NewScanCoordinator() *ScanCoordinator {
	return &ScanCoordinator{
		broadcast: make(chan struct{}),
	}
}

// signal wakes all waiters by closing and recreating the broadcast channel.
// Must be called with mu held.
func (c *ScanCoordinator) signal() {
	close(c.broadcast)
	c.broadcast = make(chan struct{})
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
	for c.updating {
		// Capture current broadcast channel while holding lock.
		wait := c.broadcast
		c.mu.Unlock()

		// Wait for either broadcast signal or context cancellation.
		select {
		case <-wait:
			// State changed, re-acquire lock and re-check condition.
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		c.mu.Lock()
	}

	// Increment active scans while holding lock.
	c.activeScans++
	c.mu.Unlock()

	// Return release function with once guard.
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.activeScans--
			if c.activeScans == 0 {
				c.signal()
			}
			c.mu.Unlock()
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
	for c.updating || c.activeScans > 0 {
		// Capture current broadcast channel while holding lock.
		wait := c.broadcast
		c.mu.Unlock()

		// Wait for either broadcast signal or context cancellation.
		select {
		case <-wait:
			// State changed, re-acquire lock and re-check condition.
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		c.mu.Lock()
	}

	// Mark update as in progress while holding lock.
	c.updating = true
	c.mu.Unlock()

	// Return release function with once guard.
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.updating = false
			c.signal()
			c.mu.Unlock()
		})
	}, nil
}

// HasActiveScans returns true if there are any active scan operations.
func (c *ScanCoordinator) HasActiveScans() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeScans > 0
}

// IsUpdating returns true if an update operation is in progress.
func (c *ScanCoordinator) IsUpdating() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.updating
}

// Status returns the current coordinator status.
func (c *ScanCoordinator) Status() CoordinatorStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CoordinatorStatus{
		ActiveScans:      int(c.activeScans),
		UpdateInProgress: c.updating,
	}
}
