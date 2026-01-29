// ABOUTME: ClamAV database manager for clamscan mode
// ABOUTME: Downloads and manages CVD files (main.cvd, daily.cvd, bytecode.cvd)

package feeds

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ClamAVDBFeed manages ClamAV database files for clamscan.
// Unlike ClamAVFeed which extracts signatures, this feed saves raw CVD files
// for use with the clamscan binary.
type ClamAVDBFeed struct {
	databaseDir string
	mirrors     []string
	databases   []string
	downloader  *Downloader
}

// UpdateStats contains statistics from a database update.
type UpdateStats struct {
	Downloaded int // Number of databases downloaded.
	Skipped    int // Number of databases skipped (up-to-date).
	Failed     int // Number of databases that failed.
}

// String returns a human-readable summary.
func (s *UpdateStats) String() string {
	return fmt.Sprintf("downloaded: %d, skipped: %d, failed: %d",
		s.Downloaded, s.Skipped, s.Failed)
}

// NewClamAVDBFeed creates a new ClamAV database manager.
// databaseDir is where CVD files will be stored.
func NewClamAVDBFeed(databaseDir string) *ClamAVDBFeed {
	return &ClamAVDBFeed{
		databaseDir: databaseDir,
		mirrors:     ClamAVMirrors,
		databases:   []string{ClamAVMainDB, ClamAVDailyDB},
		downloader:  NewDownloader(nil),
	}
}

// Name returns the name of the feed.
func (f *ClamAVDBFeed) Name() string {
	return "clamav-db"
}

// SetMirrors overrides the default mirrors.
func (f *ClamAVDBFeed) SetMirrors(mirrors []string) {
	f.mirrors = mirrors
}

// SetDatabases sets which databases to download.
func (f *ClamAVDBFeed) SetDatabases(databases []string) {
	f.databases = databases
}

// Update downloads and saves ClamAV databases.
// It checks local versions and only downloads if updates are available.
func (f *ClamAVDBFeed) Update(ctx context.Context) (*UpdateStats, error) {
	// Create database directory if it doesn't exist.
	if err := os.MkdirAll(f.databaseDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	stats := &UpdateStats{}

	for _, db := range f.databases {
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		default:
		}

		updated, err := f.updateDatabase(ctx, db)
		if err != nil {
			fmt.Printf("Warning: failed to update %s: %v\n", db, err)
			stats.Failed++
			continue
		}

		if updated {
			stats.Downloaded++
		} else {
			stats.Skipped++
		}
	}

	return stats, nil
}

// updateDatabase downloads a single database if needed.
// Returns true if the database was updated, false if already up-to-date.
func (f *ClamAVDBFeed) updateDatabase(ctx context.Context, database string) (bool, error) {
	localVersion, _ := f.GetLocalVersion(database)

	// Try each mirror.
	var lastErr error
	for _, mirror := range f.mirrors {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}

		url := fmt.Sprintf("%s/%s", strings.TrimSuffix(mirror, "/"), database)

		data, err := f.downloader.Download(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}

		// Parse header to get version.
		if len(data) < cvdHeaderSize {
			lastErr = fmt.Errorf("downloaded data too small: %d bytes", len(data))
			continue
		}

		header, err := parseCVDHeader(data[:cvdHeaderSize])
		if err != nil {
			lastErr = fmt.Errorf("parsing CVD header: %w", err)
			continue
		}

		// Skip if local version is current.
		if header.Version > 0 && localVersion >= header.Version {
			return false, nil
		}

		// Save the database atomically.
		if err := f.saveDatabase(database, data); err != nil {
			lastErr = fmt.Errorf("saving database: %w", err)
			continue
		}

		return true, nil
	}

	return false, fmt.Errorf("failed to update %s from all mirrors: %w", database, lastErr)
}

// saveDatabase saves data to the database file atomically.
func (f *ClamAVDBFeed) saveDatabase(database string, data []byte) error {
	targetPath := filepath.Join(f.databaseDir, database)
	tmpPath := targetPath + ".tmp"

	// Write to temporary file.
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}

	// Atomic rename.
	if err := os.Rename(tmpPath, targetPath); err != nil {
		os.Remove(tmpPath) // Clean up on failure.
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}

// GetLocalVersion reads the version from a local CVD file.
// Returns 0 and an error if the file doesn't exist or is invalid.
func (f *ClamAVDBFeed) GetLocalVersion(database string) (int, error) {
	path := filepath.Join(f.databaseDir, database)

	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening database file: %w", err)
	}
	defer file.Close()

	// Read header.
	header := make([]byte, cvdHeaderSize)
	n, err := file.Read(header)
	if err != nil {
		return 0, fmt.Errorf("reading header: %w", err)
	}
	if n < cvdHeaderSize {
		return 0, fmt.Errorf("file too small: %d bytes", n)
	}

	// Parse header.
	cvdHeader, err := parseCVDHeader(header)
	if err != nil {
		return 0, fmt.Errorf("parsing header: %w", err)
	}

	return cvdHeader.Version, nil
}

// GetDatabasePath returns the full path to a database file.
func (f *ClamAVDBFeed) GetDatabasePath(database string) string {
	return filepath.Join(f.databaseDir, database)
}

// DatabaseDir returns the database directory.
func (f *ClamAVDBFeed) DatabaseDir() string {
	return f.databaseDir
}

// IsReady checks if the minimum required databases are present.
func (f *ClamAVDBFeed) IsReady() bool {
	// At minimum, we need main.cvd or daily.cvd.
	mainPath := filepath.Join(f.databaseDir, ClamAVMainDB)
	dailyPath := filepath.Join(f.databaseDir, ClamAVDailyDB)

	_, mainErr := os.Stat(mainPath)
	_, dailyErr := os.Stat(dailyPath)

	return mainErr == nil || dailyErr == nil
}

// GetVersionInfo returns version information for all databases.
func (f *ClamAVDBFeed) GetVersionInfo() map[string]int {
	versions := make(map[string]int)

	for _, db := range f.databases {
		version, err := f.GetLocalVersion(db)
		if err == nil {
			versions[db] = version
		}
	}

	return versions
}

// parseCVDHeaderVersion extracts version from CVD header bytes.
func parseCVDHeaderVersion(data []byte) (int, error) {
	if len(data) < cvdHeaderSize {
		return 0, fmt.Errorf("data too small for CVD header")
	}

	headerStr := string(bytes.TrimRight(data[:cvdHeaderSize], "\x00"))
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
