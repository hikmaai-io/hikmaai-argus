// ABOUTME: Trivy database updater implementation
// ABOUTME: Downloads vulnerability DB using trivy binary with metadata tracking

package dbupdater

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Default Trivy configuration values.
const (
	DefaultTrivyBinary  = "trivy"
	DefaultTrivyTimeout = 10 * time.Minute
)

// TrivyMetadata represents the trivy database metadata.json structure.
type TrivyMetadata struct {
	// Version is the database schema version.
	Version int `json:"Version"`

	// NextUpdate is when the next update is expected.
	NextUpdate time.Time `json:"NextUpdate"`

	// UpdatedAt is when the database was last updated.
	UpdatedAt time.Time `json:"UpdatedAt"`
}

// TrivyUpdaterConfig configures the Trivy updater.
type TrivyUpdaterConfig struct {
	// CacheDir is the trivy cache directory where the DB is stored.
	CacheDir string

	// Binary is the path to the trivy binary.
	// If empty, defaults to "trivy".
	Binary string

	// Timeout for update operations.
	// If zero, defaults to DefaultTrivyTimeout.
	Timeout time.Duration

	// SkipJavaDB skips downloading the Java vulnerability database.
	SkipJavaDB bool
}

// TrivyUpdater updates the Trivy vulnerability database.
type TrivyUpdater struct {
	config TrivyUpdaterConfig
}

// NewTrivyUpdater creates a new Trivy updater.
func NewTrivyUpdater(config TrivyUpdaterConfig) *TrivyUpdater {
	// Apply defaults.
	if config.Binary == "" {
		config.Binary = DefaultTrivyBinary
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultTrivyTimeout
	}

	return &TrivyUpdater{
		config: config,
	}
}

// Name returns the updater identifier.
func (u *TrivyUpdater) Name() string {
	return "trivy"
}

// Update performs the database update.
func (u *TrivyUpdater) Update(ctx context.Context) (*UpdateResult, error) {
	start := time.Now()

	// Check context first.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Create timeout context if needed.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, u.config.Timeout)
		defer cancel()
	}

	// Build trivy command for downloading DB.
	// trivy image --download-db-only --cache-dir <dir>
	args := []string{
		"image",
		"--download-db-only",
	}

	if u.config.CacheDir != "" {
		args = append(args, "--cache-dir", u.config.CacheDir)
	}

	if u.config.SkipJavaDB {
		args = append(args, "--skip-java-db-update")
	}

	cmd := exec.CommandContext(ctx, u.config.Binary, args...)
	output, err := cmd.CombinedOutput()

	result := &UpdateResult{
		Duration: time.Since(start),
	}

	if err != nil {
		result.Success = false
		result.Failed = 1
		result.Error = fmt.Sprintf("trivy update failed: %v (output: %s)", err, string(output))
		return result, err
	}

	result.Success = true
	result.Downloaded = 1

	// Read version info after update.
	metadata, err := u.ReadMetadata()
	if err == nil {
		result.Versions = map[string]int{
			"trivy-db": metadata.Version,
		}
	}

	return result, nil
}

// CheckForUpdates checks if an update is available without downloading.
func (u *TrivyUpdater) CheckForUpdates(ctx context.Context) (*CheckResult, error) {
	// Check context first.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	result := &CheckResult{
		Details: make(map[string]string),
	}

	// Read current metadata.
	metadata, err := u.ReadMetadata()
	if err != nil {
		// No metadata means we definitely need an update.
		result.UpdateAvailable = true
		result.Details["status"] = "no metadata file, update required"
		return result, nil
	}

	result.CurrentVersion = metadata.Version

	// Check if NextUpdate time has passed.
	if time.Now().After(metadata.NextUpdate) {
		result.UpdateAvailable = true
		result.Details["reason"] = "NextUpdate time has passed"
		result.Details["next_update"] = metadata.NextUpdate.Format(time.RFC3339)
	} else {
		result.UpdateAvailable = false
		result.Details["status"] = "up-to-date"
		result.Details["next_update"] = metadata.NextUpdate.Format(time.RFC3339)
	}

	return result, nil
}

// GetVersionInfo returns the current database version information.
func (u *TrivyUpdater) GetVersionInfo() VersionInfo {
	metadata, err := u.ReadMetadata()
	if err != nil {
		return VersionInfo{}
	}

	return VersionInfo{
		Version:   metadata.Version,
		BuildTime: metadata.UpdatedAt,
		DBFiles: map[string]int{
			"trivy.db": metadata.Version,
		},
	}
}

// IsReady returns true if the database is present and ready.
func (u *TrivyUpdater) IsReady() bool {
	dbPath := u.DBPath()
	_, err := os.Stat(dbPath)
	return err == nil
}

// ReadMetadata reads the trivy metadata.json file.
func (u *TrivyUpdater) ReadMetadata() (*TrivyMetadata, error) {
	metadataPath := filepath.Join(u.config.CacheDir, "db", "metadata.json")

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("reading metadata.json: %w", err)
	}

	var metadata TrivyMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("parsing metadata.json: %w", err)
	}

	return &metadata, nil
}

// DBPath returns the path to the trivy database file.
func (u *TrivyUpdater) DBPath() string {
	return filepath.Join(u.config.CacheDir, "db", "trivy.db")
}

// CacheDir returns the cache directory path.
func (u *TrivyUpdater) CacheDir() string {
	return u.config.CacheDir
}

// MetadataPath returns the path to the metadata.json file.
func (u *TrivyUpdater) MetadataPath() string {
	return filepath.Join(u.config.CacheDir, "db", "metadata.json")
}
