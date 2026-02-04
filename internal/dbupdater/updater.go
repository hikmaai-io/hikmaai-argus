// ABOUTME: Updater interface and result types for database updates
// ABOUTME: Defines contract for ClamAV, Trivy, and other scanner DB updaters

package dbupdater

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Updater defines the interface for scanner database updaters.
type Updater interface {
	// Name returns the updater identifier (e.g., "clamav", "trivy").
	Name() string

	// Update performs the database update operation.
	// Returns an UpdateResult with details about what was updated.
	Update(ctx context.Context) (*UpdateResult, error)

	// CheckForUpdates checks if updates are available without downloading.
	// Returns a CheckResult indicating if an update is needed.
	CheckForUpdates(ctx context.Context) (*CheckResult, error)

	// GetVersionInfo returns current database version information.
	GetVersionInfo() VersionInfo

	// IsReady returns true if the databases are ready for scanning.
	IsReady() bool
}

// UpdateResult contains the outcome of an update operation.
type UpdateResult struct {
	// Success indicates if the update completed successfully.
	Success bool

	// Downloaded is the number of databases downloaded.
	Downloaded int

	// Skipped is the number of databases skipped (already up-to-date).
	Skipped int

	// Failed is the number of databases that failed to update.
	Failed int

	// Duration is how long the update took.
	Duration time.Duration

	// Error is the error message if the update failed.
	Error string

	// Versions maps database names to their new versions.
	Versions map[string]int
}

// HasErrors returns true if the result indicates any errors occurred.
func (r *UpdateResult) HasErrors() bool {
	return r.Failed > 0 || r.Error != ""
}

// String returns a human-readable summary of the update result.
func (r *UpdateResult) String() string {
	var parts []string

	if r.Success {
		parts = append(parts, "success")
	} else {
		parts = append(parts, "failed")
	}

	parts = append(parts, fmt.Sprintf("downloaded=%d", r.Downloaded))
	parts = append(parts, fmt.Sprintf("skipped=%d", r.Skipped))

	if r.Failed > 0 {
		parts = append(parts, fmt.Sprintf("failed=%d", r.Failed))
	}

	parts = append(parts, fmt.Sprintf("duration=%v", r.Duration))

	if r.Error != "" {
		parts = append(parts, fmt.Sprintf("error=%q", r.Error))
	}

	return strings.Join(parts, " ")
}

// CheckResult contains the outcome of checking for updates.
type CheckResult struct {
	// UpdateAvailable indicates if an update is available.
	UpdateAvailable bool

	// CurrentVersion is the currently installed version.
	CurrentVersion int

	// AvailableVersion is the version available for download.
	AvailableVersion int

	// Details provides additional information about what would be updated.
	Details map[string]string
}

// NeedsUpdate returns true if an update is available.
func (r *CheckResult) NeedsUpdate() bool {
	return r.UpdateAvailable
}

// String returns a human-readable summary of the version info.
func (v VersionInfo) String() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("version=%d", v.Version))

	if !v.BuildTime.IsZero() {
		parts = append(parts, fmt.Sprintf("build=%s", v.BuildTime.Format(time.RFC3339)))
	}

	if len(v.DBFiles) > 0 {
		var dbParts []string
		for name, ver := range v.DBFiles {
			dbParts = append(dbParts, fmt.Sprintf("%s=%d", name, ver))
		}
		parts = append(parts, fmt.Sprintf("files={%s}", strings.Join(dbParts, ",")))
	}

	return strings.Join(parts, " ")
}
