// ABOUTME: Tests for archive extraction decompression-bomb limits
// ABOUTME: Verifies per-file, total-size, and entry-count caps

package trivy

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeZip(t *testing.T, files map[string]int) string {
	t.Helper()
	zipPath := filepath.Join(t.TempDir(), "bomb.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer zf.Close()

	w := zip.NewWriter(zf)
	for name, size := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("create entry: %v", err)
		}
		// Highly compressible payload to mimic a zip bomb.
		if _, err := f.Write([]byte(strings.Repeat("A", size))); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return zipPath
}

func TestExtractArchiveWithLimits_PerFileCap(t *testing.T) {
	t.Parallel()

	zipPath := writeZip(t, map[string]int{"big.txt": 5 * 1024 * 1024})

	extractDir, err := ExtractArchiveWithLimits(zipPath, ExtractLimits{MaxFileSize: 1024})
	if err == nil {
		os.RemoveAll(extractDir)
		t.Fatal("expected per-file size limit error, got nil")
	}
	if !strings.Contains(err.Error(), "size limit") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}

func TestExtractArchiveWithLimits_TotalCap(t *testing.T) {
	t.Parallel()

	zipPath := writeZip(t, map[string]int{
		"a.txt": 800 * 1024,
		"b.txt": 800 * 1024,
		"c.txt": 800 * 1024,
	})

	extractDir, err := ExtractArchiveWithLimits(zipPath, ExtractLimits{
		MaxFileSize:  1024 * 1024,
		MaxTotalSize: 1024 * 1024, // total budget smaller than sum of files
	})
	if err == nil {
		os.RemoveAll(extractDir)
		t.Fatal("expected total size limit error, got nil")
	}
	if !strings.Contains(err.Error(), "size limit") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}

func TestExtractArchiveWithLimits_EntryCount(t *testing.T) {
	t.Parallel()

	files := make(map[string]int)
	for i := 0; i < 20; i++ {
		files[filepath.Join("dir", "f"+string(rune('a'+i))+".txt")] = 8
	}
	zipPath := writeZip(t, files)

	extractDir, err := ExtractArchiveWithLimits(zipPath, ExtractLimits{MaxEntries: 5})
	if err == nil {
		os.RemoveAll(extractDir)
		t.Fatal("expected entry count limit error, got nil")
	}
	if !strings.Contains(err.Error(), "too many entries") {
		t.Errorf("expected entry count error, got: %v", err)
	}
}

func TestExtractArchiveWithLimits_WithinLimits(t *testing.T) {
	t.Parallel()

	zipPath := writeZip(t, map[string]int{"requirements.txt": 32})

	extractDir, err := ExtractArchiveWithLimits(zipPath, ExtractLimits{})
	if err != nil {
		t.Fatalf("unexpected error within limits: %v", err)
	}
	defer os.RemoveAll(extractDir)

	if _, err := os.Stat(filepath.Join(extractDir, "requirements.txt")); err != nil {
		t.Errorf("expected extracted file present: %v", err)
	}
}
