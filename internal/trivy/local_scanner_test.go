// ABOUTME: Unit tests for local Trivy scanner using trivy CLI
// ABOUTME: Tests filesystem scanning and archive handling

package trivy

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalScanner_Ping(t *testing.T) {
	t.Parallel()

	scanner := NewLocalScanner(LocalScannerConfig{
		Binary:  "trivy",
		Timeout: 30 * time.Second,
	})

	ctx := context.Background()
	err := scanner.Ping(ctx)

	// This test will skip if trivy is not installed.
	if err != nil {
		t.Skipf("trivy not available: %v", err)
	}
}

func TestLocalScanner_ScanFS_Directory(t *testing.T) {
	t.Parallel()

	// Check if trivy is available.
	scanner := NewLocalScanner(LocalScannerConfig{
		Binary:       "trivy",
		Timeout:      2 * time.Minute,
		SkipDBUpdate: true, // Speed up test.
	})

	ctx := context.Background()
	if err := scanner.Ping(ctx); err != nil {
		t.Skipf("trivy not available: %v", err)
	}

	// Create temp directory with a requirements.txt.
	dir := t.TempDir()
	content := []byte("requests==2.25.0\nflask==2.0.0")
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), content, 0o644); err != nil {
		t.Fatalf("failed to write requirements.txt: %v", err)
	}

	// Scan the directory.
	opts := ScanOptions{
		SeverityFilter: []string{SeverityCritical, SeverityHigh},
		ScanSecrets:    true,
	}

	result, err := scanner.ScanFS(ctx, dir, opts)
	if err != nil {
		t.Fatalf("ScanFS() error = %v", err)
	}

	// Verify result structure.
	if result.ScannedAt.IsZero() {
		t.Error("ScannedAt should not be zero")
	}
	if result.ScanTimeMs <= 0 {
		t.Error("ScanTimeMs should be positive")
	}
}

func TestLocalScanner_ScanPath_Archive(t *testing.T) {
	t.Parallel()

	// Check if trivy is available.
	scanner := NewLocalScanner(LocalScannerConfig{
		Binary:       "trivy",
		Timeout:      2 * time.Minute,
		SkipDBUpdate: true,
	})

	ctx := context.Background()
	if err := scanner.Ping(ctx); err != nil {
		t.Skipf("trivy not available: %v", err)
	}

	// Create a zip with a package.json.
	zipPath := filepath.Join(t.TempDir(), "test.zip")
	createTestZip(t, zipPath, map[string]string{
		"package.json": `{"dependencies":{"lodash":"4.17.20"}}`,
	})

	// Scan the archive.
	opts := ScanOptions{
		SeverityFilter: []string{SeverityCritical, SeverityHigh},
		ScanSecrets:    true,
	}

	result, err := scanner.ScanPath(ctx, zipPath, opts)
	if err != nil {
		t.Fatalf("ScanPath() error = %v", err)
	}

	// Verify result.
	if result.ScannedAt.IsZero() {
		t.Error("ScannedAt should not be zero")
	}
}

func TestMapTypeToEcosystem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		trivyType string
		want      string
	}{
		{"pip", EcosystemPip},
		{"pipenv", EcosystemPip},
		{"poetry", EcosystemPip},
		{"npm", EcosystemNpm},
		{"yarn", EcosystemNpm},
		{"pnpm", EcosystemNpm},
		{"gomod", EcosystemGomod},
		{"cargo", EcosystemCargo},
		{"composer", EcosystemComposer},
		{"bundler", EcosystemRubygems},
		{"pom", EcosystemMaven},
		{"gradle", EcosystemMaven},
		{"nuget", EcosystemNuget},
		{"unknown-type", "unknown-type"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.trivyType, func(t *testing.T) {
			t.Parallel()
			got := mapTypeToEcosystem(tt.trivyType)
			if got != tt.want {
				t.Errorf("mapTypeToEcosystem(%q) = %q, want %q", tt.trivyType, got, tt.want)
			}
		})
	}
}

// createTestZip creates a zip file with the given files.
func createTestZip(t *testing.T, zipPath string, files map[string]string) {
	t.Helper()

	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}

	w := zip.NewWriter(zipFile)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("failed to create file in zip: %v", err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write to zip: %v", err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	if err := zipFile.Close(); err != nil {
		t.Fatalf("failed to close zip file: %v", err)
	}
}
