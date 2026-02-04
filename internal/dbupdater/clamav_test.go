// ABOUTME: Tests for ClamAV database updater implementation
// ABOUTME: Validates update logic, version checking, and clamd reload

package dbupdater

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// createTestCVD creates a minimal valid CVD file for testing.
func createTestCVD(version int) []byte {
	header := make([]byte, 512)
	headerStr := fmt.Sprintf("ClamAV-VDB:01 Jan 2024 00-00 +0000:%d:100000:77:abc123:def456:builder:1704067200", version)
	copy(header, headerStr)

	gzipData := []byte{
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	return append(header, gzipData...)
}

func TestClamAVUpdater_Name(t *testing.T) {
	t.Parallel()

	updater := NewClamAVUpdater(ClamAVUpdaterConfig{
		DatabaseDir: t.TempDir(),
	})

	if got := updater.Name(); got != "clamav" {
		t.Errorf("Name() = %q, want %q", got, "clamav")
	}
}

func TestClamAVUpdater_Update_Success(t *testing.T) {
	t.Parallel()

	testData := createTestCVD(100)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testData)
	}))
	defer server.Close()

	dbDir := t.TempDir()
	updater := NewClamAVUpdater(ClamAVUpdaterConfig{
		DatabaseDir: dbDir,
		Mirrors:     []string{server.URL},
		Databases:   []string{"test.cvd"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := updater.Update(ctx)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Update() Success = false, want true")
	}
	if result.Downloaded != 1 {
		t.Errorf("Downloaded = %d, want 1", result.Downloaded)
	}

	// File should exist.
	if _, err := os.Stat(filepath.Join(dbDir, "test.cvd")); err != nil {
		t.Errorf("Database file not created: %v", err)
	}
}

func TestClamAVUpdater_Update_AlreadyUpToDate(t *testing.T) {
	t.Parallel()

	testData := createTestCVD(100)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testData)
	}))
	defer server.Close()

	dbDir := t.TempDir()

	// Pre-create the database file.
	if err := os.WriteFile(filepath.Join(dbDir, "test.cvd"), testData, 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	updater := NewClamAVUpdater(ClamAVUpdaterConfig{
		DatabaseDir: dbDir,
		Mirrors:     []string{server.URL},
		Databases:   []string{"test.cvd"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := updater.Update(ctx)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if result.Downloaded != 0 {
		t.Errorf("Downloaded = %d, want 0 (already up to date)", result.Downloaded)
	}
	if result.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", result.Skipped)
	}
}

func TestClamAVUpdater_Update_ContextCancellation(t *testing.T) {
	t.Parallel()

	// Server that delays response.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(10 * time.Second):
			w.Write(createTestCVD(1))
		}
	}))
	defer server.Close()

	updater := NewClamAVUpdater(ClamAVUpdaterConfig{
		DatabaseDir: t.TempDir(),
		Mirrors:     []string{server.URL},
		Databases:   []string{"test.cvd"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := updater.Update(ctx)
	if err == nil {
		t.Error("Update() should error on context cancellation")
	}
}

func TestClamAVUpdater_CheckForUpdates(t *testing.T) {
	t.Parallel()

	testData := createTestCVD(100)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testData)
	}))
	defer server.Close()

	dbDir := t.TempDir()

	// Pre-create with older version.
	oldData := createTestCVD(50)
	if err := os.WriteFile(filepath.Join(dbDir, "test.cvd"), oldData, 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	updater := NewClamAVUpdater(ClamAVUpdaterConfig{
		DatabaseDir: dbDir,
		Mirrors:     []string{server.URL},
		Databases:   []string{"test.cvd"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := updater.CheckForUpdates(ctx)
	if err != nil {
		t.Fatalf("CheckForUpdates() error = %v", err)
	}

	if !result.UpdateAvailable {
		t.Error("CheckForUpdates() UpdateAvailable = false, want true")
	}
}

func TestClamAVUpdater_GetVersionInfo(t *testing.T) {
	t.Parallel()

	dbDir := t.TempDir()

	// Create test CVD files.
	mainData := createTestCVD(12345)
	dailyData := createTestCVD(67890)

	if err := os.WriteFile(filepath.Join(dbDir, "main.cvd"), mainData, 0o644); err != nil {
		t.Fatalf("Failed to create main.cvd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "daily.cvd"), dailyData, 0o644); err != nil {
		t.Fatalf("Failed to create daily.cvd: %v", err)
	}

	updater := NewClamAVUpdater(ClamAVUpdaterConfig{
		DatabaseDir: dbDir,
		Databases:   []string{"main.cvd", "daily.cvd"},
	})

	info := updater.GetVersionInfo()

	if info.DBFiles == nil {
		t.Fatal("DBFiles should not be nil")
	}
	if len(info.DBFiles) != 2 {
		t.Errorf("DBFiles has %d entries, want 2", len(info.DBFiles))
	}
}

func TestClamAVUpdater_IsReady(t *testing.T) {
	t.Parallel()

	dbDir := t.TempDir()
	updater := NewClamAVUpdater(ClamAVUpdaterConfig{
		DatabaseDir: dbDir,
		Databases:   []string{"main.cvd", "daily.cvd"},
	})

	// Not ready without databases.
	if updater.IsReady() {
		t.Error("IsReady() should be false without databases")
	}

	// Create at least one database.
	if err := os.WriteFile(filepath.Join(dbDir, "main.cvd"), createTestCVD(1), 0o644); err != nil {
		t.Fatalf("Failed to create main.cvd: %v", err)
	}

	// Should be ready now.
	if !updater.IsReady() {
		t.Error("IsReady() should be true with main.cvd present")
	}
}

func TestClamAVUpdater_ImplementsUpdater(t *testing.T) {
	t.Parallel()

	var _ Updater = (*ClamAVUpdater)(nil)
}

func TestClamAVUpdaterConfig_Defaults(t *testing.T) {
	t.Parallel()

	updater := NewClamAVUpdater(ClamAVUpdaterConfig{
		DatabaseDir: t.TempDir(),
	})

	// Should have default mirrors and databases.
	if len(updater.config.Mirrors) == 0 {
		t.Error("Should have default mirrors")
	}
	if len(updater.config.Databases) == 0 {
		t.Error("Should have default databases")
	}
}
