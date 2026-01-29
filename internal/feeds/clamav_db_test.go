// ABOUTME: Tests for ClamAV database manager (CVD file management)
// ABOUTME: Validates download, version check, and atomic file operations

package feeds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// createTestCVD creates a minimal valid CVD file for testing.
// CVD format: 512-byte header (colon-separated) + tar.gz data.
func createTestCVD(version int) []byte {
	// Header format: ClamAV-VDB:build_time:version:sigs:functionality:md5:signature:builder:time
	header := make([]byte, 512)
	headerStr := fmt.Sprintf("ClamAV-VDB:01 Jan 2024 00-00 +0000:%d:100000:77:abc123:def456:builder:1704067200", version)
	copy(header, headerStr)

	// Minimal gzip content (empty but valid).
	gzipData := []byte{
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	return append(header, gzipData...)
}

func TestClamAVDBFeed_Name(t *testing.T) {
	t.Parallel()

	feed := NewClamAVDBFeed(t.TempDir())
	if got := feed.Name(); got != "clamav-db" {
		t.Errorf("Name() = %q, want %q", got, "clamav-db")
	}
}

func TestClamAVDBFeed_Update_CreatesDirectory(t *testing.T) {
	t.Parallel()

	// Create test server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(createTestCVD(1))
	}))
	defer server.Close()

	// Use non-existent directory.
	dbDir := filepath.Join(t.TempDir(), "clamav", "db")

	feed := NewClamAVDBFeed(dbDir)
	feed.SetMirrors([]string{server.URL})
	feed.SetDatabases([]string{"test.cvd"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stats, err := feed.Update(ctx)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Directory should be created.
	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		t.Error("Database directory was not created")
	}

	if stats.Downloaded != 1 {
		t.Errorf("Downloaded = %d, want 1", stats.Downloaded)
	}
}

func TestClamAVDBFeed_Update_SavesFile(t *testing.T) {
	t.Parallel()

	testData := createTestCVD(1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testData)
	}))
	defer server.Close()

	dbDir := t.TempDir()
	feed := NewClamAVDBFeed(dbDir)
	feed.SetMirrors([]string{server.URL})
	feed.SetDatabases([]string{"test.cvd"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := feed.Update(ctx)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// File should exist.
	savedPath := filepath.Join(dbDir, "test.cvd")
	data, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("Failed to read saved file: %v", err)
	}

	if len(data) != len(testData) {
		t.Errorf("Saved file size = %d, want %d", len(data), len(testData))
	}
}

func TestClamAVDBFeed_Update_SkipsUpToDate(t *testing.T) {
	t.Parallel()

	testData := createTestCVD(1)

	downloadCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloadCount++
		w.Write(testData)
	}))
	defer server.Close()

	dbDir := t.TempDir()
	feed := NewClamAVDBFeed(dbDir)
	feed.SetMirrors([]string{server.URL})
	feed.SetDatabases([]string{"test.cvd"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First update.
	stats1, err := feed.Update(ctx)
	if err != nil {
		t.Fatalf("First Update() error = %v", err)
	}
	if stats1.Downloaded != 1 {
		t.Errorf("First update: Downloaded = %d, want 1", stats1.Downloaded)
	}

	// Second update should skip (same version).
	stats2, err := feed.Update(ctx)
	if err != nil {
		t.Fatalf("Second Update() error = %v", err)
	}
	if stats2.Skipped != 1 {
		t.Errorf("Second update: Skipped = %d, want 1", stats2.Skipped)
	}
	if stats2.Downloaded != 0 {
		t.Errorf("Second update: Downloaded = %d, want 0", stats2.Downloaded)
	}
}

func TestClamAVDBFeed_GetLocalVersion(t *testing.T) {
	t.Parallel()

	dbDir := t.TempDir()
	feed := NewClamAVDBFeed(dbDir)

	// No file exists.
	version, err := feed.GetLocalVersion("test.cvd")
	if err == nil {
		t.Error("GetLocalVersion() should error for non-existent file")
	}
	if version != 0 {
		t.Errorf("GetLocalVersion() = %d, want 0", version)
	}

	// Create a CVD file.
	testData := createTestCVD(5)
	if err := os.WriteFile(filepath.Join(dbDir, "test.cvd"), testData, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	version, err = feed.GetLocalVersion("test.cvd")
	if err != nil {
		t.Fatalf("GetLocalVersion() error = %v", err)
	}
	if version == 0 {
		t.Error("GetLocalVersion() should return non-zero version")
	}
}

func TestClamAVDBFeed_Update_ContextCancellation(t *testing.T) {
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

	dbDir := t.TempDir()
	feed := NewClamAVDBFeed(dbDir)
	feed.SetMirrors([]string{server.URL})
	feed.SetDatabases([]string{"test.cvd"})

	// Cancel immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := feed.Update(ctx)
	if err == nil {
		t.Error("Update() should error on context cancellation")
	}
}

func TestClamAVDBFeed_Update_AtomicWrite(t *testing.T) {
	t.Parallel()

	testData := createTestCVD(1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testData)
	}))
	defer server.Close()

	dbDir := t.TempDir()
	feed := NewClamAVDBFeed(dbDir)
	feed.SetMirrors([]string{server.URL})
	feed.SetDatabases([]string{"test.cvd"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := feed.Update(ctx)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// No .tmp files should remain.
	entries, _ := os.ReadDir(dbDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("Temporary file %s was not cleaned up", e.Name())
		}
	}
}

func TestClamAVDBFeed_Update_AllDatabases(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(createTestCVD(1))
	}))
	defer server.Close()

	dbDir := t.TempDir()
	feed := NewClamAVDBFeed(dbDir)
	feed.SetMirrors([]string{server.URL})
	// Use default databases.

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stats, err := feed.Update(ctx)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Should have downloaded main.cvd and daily.cvd (default databases).
	if stats.Downloaded < 2 {
		t.Errorf("Downloaded = %d, want >= 2", stats.Downloaded)
	}
}

func TestUpdateStats_String(t *testing.T) {
	t.Parallel()

	stats := &UpdateStats{
		Downloaded: 2,
		Skipped:    1,
		Failed:     0,
	}

	str := stats.String()
	if !strings.Contains(str, "2") {
		t.Error("String() should contain downloaded count")
	}
	if !strings.Contains(str, "1") {
		t.Error("String() should contain skipped count")
	}
}
