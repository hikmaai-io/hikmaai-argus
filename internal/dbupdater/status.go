// ABOUTME: Status tracking types for DB updater service
// ABOUTME: Thread-safe tracker for monitoring updater health and versions

package dbupdater

import (
	"sync"
	"time"
)

// Status represents the current status of an updater.
type Status string

// Status constants for updater states.
const (
	// StatusPending indicates the updater has not run yet.
	StatusPending Status = "pending"

	// StatusIdle indicates the updater is idle (last update successful).
	StatusIdle Status = "idle"

	// StatusUpdating indicates an update is in progress.
	StatusUpdating Status = "updating"

	// StatusFailed indicates the last update failed.
	StatusFailed Status = "failed"
)

// VersionInfo holds version information for a database.
type VersionInfo struct {
	// Version is the primary version number.
	Version int

	// BuildTime is when the database was built.
	BuildTime time.Time

	// DBFiles maps database file names to their versions.
	// For ClamAV: {"main.cvd": 12345, "daily.cvd": 67890}
	DBFiles map[string]int
}

// UpdaterStatus represents the status of a single updater.
type UpdaterStatus struct {
	// Name is the updater identifier.
	Name string

	// Status is the current operational status.
	Status Status

	// LastUpdate is when the last successful update occurred.
	LastUpdate time.Time

	// NextScheduled is when the next update is scheduled.
	NextScheduled time.Time

	// LastError is the error message from the last failed update.
	LastError string

	// Version contains database version information.
	Version VersionInfo

	// Ready indicates if the databases are ready for scanning.
	Ready bool
}

// IsReady returns true if the updater is ready for use.
func (s *UpdaterStatus) IsReady() bool {
	return s.Ready
}

// TimeSinceLastUpdate returns the duration since the last successful update.
// Returns 0 if never updated.
func (s *UpdaterStatus) TimeSinceLastUpdate() time.Duration {
	if s.LastUpdate.IsZero() {
		return 0
	}
	return time.Since(s.LastUpdate)
}

// StatusTracker manages status for multiple updaters.
type StatusTracker struct {
	mu       sync.RWMutex
	statuses map[string]*UpdaterStatus
}

// NewStatusTracker creates a new status tracker.
func NewStatusTracker() *StatusTracker {
	return &StatusTracker{
		statuses: make(map[string]*UpdaterStatus),
	}
}

// Register registers a new updater with the tracker.
func (t *StatusTracker) Register(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.statuses[name] = &UpdaterStatus{
		Name:   name,
		Status: StatusPending,
	}
}

// Get returns the status for an updater, or nil if not found.
func (t *StatusTracker) Get(name string) *UpdaterStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	status, ok := t.statuses[name]
	if !ok {
		return nil
	}

	// Return a copy to prevent modification.
	cp := *status
	if status.Version.DBFiles != nil {
		cp.Version.DBFiles = make(map[string]int, len(status.Version.DBFiles))
		for k, v := range status.Version.DBFiles {
			cp.Version.DBFiles[k] = v
		}
	}
	return &cp
}

// GetAll returns a copy of all updater statuses.
func (t *StatusTracker) GetAll() map[string]*UpdaterStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]*UpdaterStatus, len(t.statuses))
	for name, status := range t.statuses {
		cp := *status
		if status.Version.DBFiles != nil {
			cp.Version.DBFiles = make(map[string]int, len(status.Version.DBFiles))
			for k, v := range status.Version.DBFiles {
				cp.Version.DBFiles[k] = v
			}
		}
		result[name] = &cp
	}
	return result
}

// SetStatus updates the status for an updater.
func (t *StatusTracker) SetStatus(name string, status Status) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.statuses[name]; ok {
		s.Status = status
	}
}

// SetReady updates the ready state for an updater.
func (t *StatusTracker) SetReady(name string, ready bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.statuses[name]; ok {
		s.Ready = ready
	}
}

// SetLastUpdate updates the last update time for an updater.
func (t *StatusTracker) SetLastUpdate(name string, lastUpdate time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.statuses[name]; ok {
		s.LastUpdate = lastUpdate
	}
}

// SetNextScheduled updates the next scheduled time for an updater.
func (t *StatusTracker) SetNextScheduled(name string, next time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.statuses[name]; ok {
		s.NextScheduled = next
	}
}

// SetError updates the last error for an updater.
func (t *StatusTracker) SetError(name string, err string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.statuses[name]; ok {
		s.LastError = err
	}
}

// SetVersion updates the version info for an updater.
func (t *StatusTracker) SetVersion(name string, version VersionInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.statuses[name]; ok {
		// Deep copy the DBFiles map.
		cp := version
		if version.DBFiles != nil {
			cp.DBFiles = make(map[string]int, len(version.DBFiles))
			for k, v := range version.DBFiles {
				cp.DBFiles[k] = v
			}
		}
		s.Version = cp
	}
}
