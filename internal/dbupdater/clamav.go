// ABOUTME: ClamAV database updater implementation
// ABOUTME: Downloads CVD files with version checking and optional clamd reload

package dbupdater

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/feeds"
)

// ClamAV database constants.
const (
	ClamAVMainDB  = "main.cvd"
	ClamAVDailyDB = "daily.cvd"
)

// Default ClamAV mirrors.
var DefaultClamAVMirrors = []string{
	"https://database.clamav.net",
	"https://packages.microsoft.com/clamav",
}

// ClamAVUpdaterConfig configures the ClamAV updater.
type ClamAVUpdaterConfig struct {
	// DatabaseDir is where CVD files are stored.
	DatabaseDir string

	// Mirrors is the list of ClamAV mirrors to try.
	// If empty, defaults to DefaultClamAVMirrors.
	Mirrors []string

	// Databases is the list of databases to update.
	// If empty, defaults to main.cvd and daily.cvd.
	Databases []string

	// ClamdAddress is the clamd address for reload commands.
	// If empty, reload is skipped.
	// Format: "unix:///path/to/clamd.sock" or "tcp://host:port"
	ClamdAddress string
}

// ClamAVUpdater updates ClamAV databases.
type ClamAVUpdater struct {
	config ClamAVUpdaterConfig
	feed   *feeds.ClamAVDBFeed
}

// NewClamAVUpdater creates a new ClamAV updater.
func NewClamAVUpdater(config ClamAVUpdaterConfig) *ClamAVUpdater {
	// Apply defaults.
	if len(config.Mirrors) == 0 {
		config.Mirrors = DefaultClamAVMirrors
	}
	if len(config.Databases) == 0 {
		config.Databases = []string{ClamAVMainDB, ClamAVDailyDB}
	}

	feed := feeds.NewClamAVDBFeed(config.DatabaseDir)
	feed.SetMirrors(config.Mirrors)
	feed.SetDatabases(config.Databases)

	return &ClamAVUpdater{
		config: config,
		feed:   feed,
	}
}

// Name returns the updater identifier.
func (u *ClamAVUpdater) Name() string {
	return "clamav"
}

// Update performs the database update.
func (u *ClamAVUpdater) Update(ctx context.Context) (*UpdateResult, error) {
	start := time.Now()

	// Check context first.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	stats, err := u.feed.Update(ctx)
	if err != nil {
		return &UpdateResult{
			Success:  false,
			Duration: time.Since(start),
			Error:    err.Error(),
		}, err
	}

	result := &UpdateResult{
		Success:    stats.Failed == 0,
		Downloaded: stats.Downloaded,
		Skipped:    stats.Skipped,
		Failed:     stats.Failed,
		Duration:   time.Since(start),
		Versions:   u.feed.GetVersionInfo(),
	}

	// If databases were updated and clamd address is configured, send reload.
	if stats.Downloaded > 0 && u.config.ClamdAddress != "" {
		if err := u.reloadClamd(ctx); err != nil {
			// Don't fail the update, just log/track the error.
			result.Error = fmt.Sprintf("update succeeded but reload failed: %v", err)
		}
	}

	return result, nil
}

// CheckForUpdates checks if updates are available without downloading.
func (u *ClamAVUpdater) CheckForUpdates(ctx context.Context) (*CheckResult, error) {
	// Check context first.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	result := &CheckResult{
		Details: make(map[string]string),
	}

	for _, db := range u.config.Databases {
		localVersion, _ := u.feed.GetLocalVersion(db)

		remoteVersion, err := u.checkRemoteVersion(ctx, db)
		if err != nil {
			result.Details[db] = fmt.Sprintf("error: %v", err)
			continue
		}

		if remoteVersion > localVersion {
			result.UpdateAvailable = true
			result.Details[db] = fmt.Sprintf("local=%d remote=%d", localVersion, remoteVersion)
		} else {
			result.Details[db] = fmt.Sprintf("up-to-date (version=%d)", localVersion)
		}
	}

	return result, nil
}

// checkRemoteVersion checks the version of a remote database.
func (u *ClamAVUpdater) checkRemoteVersion(ctx context.Context, database string) (int, error) {
	downloader := feeds.NewDownloader(nil)

	for _, mirror := range u.config.Mirrors {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		url := fmt.Sprintf("%s/%s", strings.TrimSuffix(mirror, "/"), database)

		// Download only the header (first 512 bytes would be ideal, but we download full).
		data, err := downloader.Download(ctx, url)
		if err != nil {
			continue
		}

		if len(data) < 512 {
			continue
		}

		version, err := parseCVDHeaderVersion(data[:512])
		if err != nil {
			continue
		}

		return version, nil
	}

	return 0, fmt.Errorf("could not check version from any mirror")
}

// parseCVDHeaderVersion extracts the version from CVD header bytes.
func parseCVDHeaderVersion(data []byte) (int, error) {
	if len(data) < 512 {
		return 0, fmt.Errorf("data too small for CVD header")
	}

	headerStr := string(bytes.TrimRight(data[:512], "\x00"))
	parts := strings.Split(headerStr, ":")

	if len(parts) < 3 {
		return 0, fmt.Errorf("invalid CVD header format")
	}

	if !strings.HasPrefix(parts[0], "ClamAV-VDB") {
		return 0, fmt.Errorf("not a valid CVD file")
	}

	var version int
	fmt.Sscanf(parts[2], "%d", &version)

	return version, nil
}

// GetVersionInfo returns the current database versions.
func (u *ClamAVUpdater) GetVersionInfo() VersionInfo {
	versions := u.feed.GetVersionInfo()

	// Find max version as the primary version.
	maxVersion := 0
	for _, v := range versions {
		if v > maxVersion {
			maxVersion = v
		}
	}

	return VersionInfo{
		Version: maxVersion,
		DBFiles: versions,
	}
}

// IsReady returns true if the minimum required databases are present.
func (u *ClamAVUpdater) IsReady() bool {
	return u.feed.IsReady()
}

// reloadClamd sends a reload command to clamd.
func (u *ClamAVUpdater) reloadClamd(ctx context.Context) error {
	address := u.config.ClamdAddress

	// Parse address.
	var network, addr string
	if strings.HasPrefix(address, "unix://") {
		network = "unix"
		addr = strings.TrimPrefix(address, "unix://")
	} else if strings.HasPrefix(address, "tcp://") {
		network = "tcp"
		addr = strings.TrimPrefix(address, "tcp://")
	} else {
		// Assume tcp if no prefix.
		network = "tcp"
		addr = address
	}

	// Try socket connection first.
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		// Fall back to clamdscan --reload.
		return u.reloadViaBinary(ctx)
	}
	defer conn.Close()

	// Set deadline.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	// Send RELOAD command.
	_, err = conn.Write([]byte("RELOAD\n"))
	if err != nil {
		return fmt.Errorf("sending RELOAD command: %w", err)
	}

	// Read response.
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("reading RELOAD response: %w", err)
	}

	response := string(buf[:n])
	if !strings.Contains(response, "RELOADING") {
		return fmt.Errorf("unexpected RELOAD response: %s", response)
	}

	return nil
}

// reloadViaBinary uses clamdscan --reload as fallback.
func (u *ClamAVUpdater) reloadViaBinary(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "clamdscan", "--reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("clamdscan --reload failed: %w (output: %s)", err, string(output))
	}
	return nil
}

// DatabaseDir returns the database directory path.
func (u *ClamAVUpdater) DatabaseDir() string {
	return u.config.DatabaseDir
}

// GetLocalVersion returns the local version of a specific database.
func (u *ClamAVUpdater) GetLocalVersion(database string) (int, error) {
	return u.feed.GetLocalVersion(database)
}

// GetDatabasePath returns the full path to a database file.
func (u *ClamAVUpdater) GetDatabasePath(database string) string {
	return filepath.Join(u.config.DatabaseDir, database)
}
