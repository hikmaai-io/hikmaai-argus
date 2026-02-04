// ABOUTME: Scanner health check system for monitoring scanner availability
// ABOUTME: Periodic verification, failure tracking, and response time metrics

package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Default health check configuration values.
const (
	DefaultCheckInterval      = 30 * time.Second
	DefaultCheckTimeout       = 10 * time.Second
	DefaultUnhealthyThreshold = 3
)

// HealthCheckFunc is a function that performs a health check.
// It should return nil if the check passes, or an error if it fails.
type HealthCheckFunc func(ctx context.Context) error

// HealthCheckerConfig configures the health checker.
type HealthCheckerConfig struct {
	// CheckInterval is how often to run health checks.
	// Zero uses DefaultCheckInterval.
	CheckInterval time.Duration

	// CheckTimeout is the timeout for individual checks.
	// Zero uses DefaultCheckTimeout.
	CheckTimeout time.Duration

	// UnhealthyThreshold is the number of consecutive failures before marking unhealthy.
	// Zero uses DefaultUnhealthyThreshold.
	UnhealthyThreshold int
}

// HealthStatus represents the health status of a scanner.
type HealthStatus struct {
	// Name is the scanner identifier.
	Name string

	// Healthy indicates if the scanner is healthy.
	Healthy bool

	// LastCheckTime is when the last health check was performed.
	LastCheckTime time.Time

	// LastError is the error from the last failed check.
	LastError string

	// ConsecutiveFailures is the number of consecutive failed checks.
	ConsecutiveFailures int

	// TotalChecks is the total number of health checks performed.
	TotalChecks int64

	// TotalFailures is the total number of failed checks.
	TotalFailures int64

	// AvgResponseTime is the average response time for checks.
	AvgResponseTime time.Duration
}

// String returns a human-readable representation.
func (s *HealthStatus) String() string {
	status := "healthy"
	if !s.Healthy {
		status = "unhealthy"
	}
	return fmt.Sprintf("%s: %s (checks=%d, failures=%d, avg_response=%v)",
		s.Name, status, s.TotalChecks, s.TotalFailures, s.AvgResponseTime)
}

// healthEntry holds a health check function and its status.
type healthEntry struct {
	checkFn HealthCheckFunc
	status  *HealthStatus

	// For calculating average response time.
	totalResponseTime time.Duration
}

// HealthChecker manages health checks for multiple scanners.
type HealthChecker struct {
	mu       sync.RWMutex
	config   HealthCheckerConfig
	checkers map[string]*healthEntry

	// For lifecycle management.
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(config HealthCheckerConfig) *HealthChecker {
	// Apply defaults.
	if config.CheckInterval == 0 {
		config.CheckInterval = DefaultCheckInterval
	}
	if config.CheckTimeout == 0 {
		config.CheckTimeout = DefaultCheckTimeout
	}
	if config.UnhealthyThreshold == 0 {
		config.UnhealthyThreshold = DefaultUnhealthyThreshold
	}

	return &HealthChecker{
		config:   config,
		checkers: make(map[string]*healthEntry),
	}
}

// Register registers a health check function for a scanner.
func (hc *HealthChecker) Register(name string, checkFn HealthCheckFunc) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.checkers[name] = &healthEntry{
		checkFn: checkFn,
		status: &HealthStatus{
			Name:    name,
			Healthy: true, // Assume healthy until proven otherwise.
		},
	}
}

// IsRegistered returns true if a scanner is registered.
func (hc *HealthChecker) IsRegistered(name string) bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	_, ok := hc.checkers[name]
	return ok
}

// IsHealthy returns true if a scanner is healthy.
func (hc *HealthChecker) IsHealthy(name string) bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	entry, ok := hc.checkers[name]
	if !ok {
		return false
	}
	return entry.status.Healthy
}

// CheckHealth performs a health check for a specific scanner.
func (hc *HealthChecker) CheckHealth(ctx context.Context, name string) error {
	hc.mu.RLock()
	entry, ok := hc.checkers[name]
	hc.mu.RUnlock()

	if !ok {
		return fmt.Errorf("scanner %q not registered", name)
	}

	// Apply timeout if not already set.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, hc.config.CheckTimeout)
		defer cancel()
	}

	start := time.Now()
	err := entry.checkFn(ctx)
	duration := time.Since(start)

	hc.mu.Lock()
	defer hc.mu.Unlock()

	entry.status.LastCheckTime = time.Now()
	entry.status.TotalChecks++
	entry.totalResponseTime += duration

	// Update average response time.
	entry.status.AvgResponseTime = entry.totalResponseTime / time.Duration(entry.status.TotalChecks)

	if err != nil {
		entry.status.ConsecutiveFailures++
		entry.status.TotalFailures++
		entry.status.LastError = err.Error()

		// Check if we've hit the unhealthy threshold.
		if entry.status.ConsecutiveFailures >= hc.config.UnhealthyThreshold {
			entry.status.Healthy = false
		}

		return err
	}

	// Success resets consecutive failures and marks healthy.
	entry.status.ConsecutiveFailures = 0
	entry.status.Healthy = true
	entry.status.LastError = ""

	return nil
}

// CheckAll performs health checks for all registered scanners.
func (hc *HealthChecker) CheckAll(ctx context.Context) map[string]error {
	hc.mu.RLock()
	names := make([]string, 0, len(hc.checkers))
	for name := range hc.checkers {
		names = append(names, name)
	}
	hc.mu.RUnlock()

	results := make(map[string]error)
	for _, name := range names {
		results[name] = hc.CheckHealth(ctx, name)
	}
	return results
}

// GetStatus returns the health status for a scanner.
func (hc *HealthChecker) GetStatus(name string) *HealthStatus {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	entry, ok := hc.checkers[name]
	if !ok {
		return nil
	}

	// Return a copy.
	cp := *entry.status
	return &cp
}

// GetAllStatuses returns health statuses for all scanners.
func (hc *HealthChecker) GetAllStatuses() map[string]*HealthStatus {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	result := make(map[string]*HealthStatus, len(hc.checkers))
	for name, entry := range hc.checkers {
		cp := *entry.status
		result[name] = &cp
	}
	return result
}

// Start begins periodic health checks.
func (hc *HealthChecker) Start(ctx context.Context) {
	hc.mu.Lock()
	if hc.running {
		hc.mu.Unlock()
		return
	}

	ctx, hc.cancel = context.WithCancel(ctx)
	hc.running = true
	hc.mu.Unlock()

	hc.wg.Add(1)
	go hc.runPeriodicChecks(ctx)
}

// Stop stops periodic health checks.
func (hc *HealthChecker) Stop() {
	hc.mu.Lock()
	if !hc.running {
		hc.mu.Unlock()
		return
	}
	hc.cancel()
	hc.running = false
	hc.mu.Unlock()

	hc.wg.Wait()
}

// runPeriodicChecks runs health checks on a schedule.
func (hc *HealthChecker) runPeriodicChecks(ctx context.Context) {
	defer hc.wg.Done()

	ticker := time.NewTicker(hc.config.CheckInterval)
	defer ticker.Stop()

	// Run initial check.
	hc.CheckAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hc.CheckAll(ctx)
		}
	}
}
