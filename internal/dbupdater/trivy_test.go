// ABOUTME: Tests for Trivy database updater implementation
// ABOUTME: Validates update logic, version checking, and cache handling

package dbupdater

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrivyUpdater_Name(t *testing.T) {
	t.Parallel()

	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: t.TempDir(),
	})

	if got := updater.Name(); got != "trivy" {
		t.Errorf("Name() = %q, want %q", got, "trivy")
	}
}

func TestTrivyUpdater_GetVersionInfo_NoMetadata(t *testing.T) {
	t.Parallel()

	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: t.TempDir(),
	})

	info := updater.GetVersionInfo()

	// Should return empty/zero values without metadata.
	if info.Version != 0 {
		t.Errorf("Version = %d, want 0 (no metadata)", info.Version)
	}
}

func TestTrivyUpdater_GetVersionInfo_WithMetadata(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	dbDir := filepath.Join(cacheDir, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatalf("Failed to create db dir: %v", err)
	}

	// Create metadata.json.
	metadataJSON := `{
		"Version": 2,
		"NextUpdate": "2024-01-15T12:00:00Z",
		"UpdatedAt": "2024-01-14T12:00:00Z"
	}`
	if err := os.WriteFile(filepath.Join(dbDir, "metadata.json"), []byte(metadataJSON), 0o644); err != nil {
		t.Fatalf("Failed to create metadata.json: %v", err)
	}

	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: cacheDir,
	})

	info := updater.GetVersionInfo()

	if info.Version != 2 {
		t.Errorf("Version = %d, want 2", info.Version)
	}
}

func TestTrivyUpdater_IsReady_NoDatabase(t *testing.T) {
	t.Parallel()

	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: t.TempDir(),
	})

	if updater.IsReady() {
		t.Error("IsReady() should be false without database")
	}
}

func TestTrivyUpdater_IsReady_WithDatabase(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	dbDir := filepath.Join(cacheDir, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatalf("Failed to create db dir: %v", err)
	}

	// Create trivy.db file (empty but present).
	if err := os.WriteFile(filepath.Join(dbDir, "trivy.db"), []byte("dummy"), 0o644); err != nil {
		t.Fatalf("Failed to create trivy.db: %v", err)
	}

	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: cacheDir,
	})

	if !updater.IsReady() {
		t.Error("IsReady() should be true with trivy.db present")
	}
}

func TestTrivyUpdater_Update_ContextCancellation(t *testing.T) {
	t.Parallel()

	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: t.TempDir(),
		Binary:   "trivy",
	})

	// Cancel context immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := updater.Update(ctx)
	if err == nil {
		t.Error("Update() should error on cancelled context")
	}
}

func TestTrivyUpdater_CheckForUpdates_ContextCancellation(t *testing.T) {
	t.Parallel()

	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: t.TempDir(),
		Binary:   "trivy",
	})

	// Cancel context immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := updater.CheckForUpdates(ctx)
	if err == nil {
		t.Error("CheckForUpdates() should error on cancelled context")
	}
}

func TestTrivyUpdater_ImplementsUpdater(t *testing.T) {
	t.Parallel()

	var _ Updater = (*TrivyUpdater)(nil)
}

func TestTrivyUpdaterConfig_Defaults(t *testing.T) {
	t.Parallel()

	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: t.TempDir(),
	})

	if updater.config.Binary == "" {
		t.Error("Binary should default to 'trivy'")
	}
	if updater.config.Timeout == 0 {
		t.Error("Timeout should have a default value")
	}
}

func TestTrivyUpdater_DBPath(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: cacheDir,
	})

	expected := filepath.Join(cacheDir, "db", "trivy.db")
	if got := updater.DBPath(); got != expected {
		t.Errorf("DBPath() = %q, want %q", got, expected)
	}
}

func TestTrivyUpdater_CacheDir(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: cacheDir,
	})

	if got := updater.CacheDir(); got != cacheDir {
		t.Errorf("CacheDir() = %q, want %q", got, cacheDir)
	}
}

func TestTrivyUpdater_ParseMetadata(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	dbDir := filepath.Join(cacheDir, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatalf("Failed to create db dir: %v", err)
	}

	// Create metadata with specific dates.
	metadataJSON := `{
		"Version": 2,
		"NextUpdate": "2024-01-15T12:00:00Z",
		"UpdatedAt": "2024-01-14T12:00:00Z"
	}`
	if err := os.WriteFile(filepath.Join(dbDir, "metadata.json"), []byte(metadataJSON), 0o644); err != nil {
		t.Fatalf("Failed to create metadata.json: %v", err)
	}

	updater := NewTrivyUpdater(TrivyUpdaterConfig{
		CacheDir: cacheDir,
	})

	metadata, err := updater.ReadMetadata()
	if err != nil {
		t.Fatalf("ReadMetadata() error = %v", err)
	}

	if metadata.Version != 2 {
		t.Errorf("Version = %d, want 2", metadata.Version)
	}

	expectedUpdate := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	if !metadata.NextUpdate.Equal(expectedUpdate) {
		t.Errorf("NextUpdate = %v, want %v", metadata.NextUpdate, expectedUpdate)
	}
}
