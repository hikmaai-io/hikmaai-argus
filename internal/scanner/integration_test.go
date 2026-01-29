// ABOUTME: Integration tests for ClamAV scanner with real clamscan binary
// ABOUTME: Tests EICAR detection, clean files, and directory scanning

//go:build integration

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/config"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// EICAR test string - standard antivirus test file.
const eicarTestString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

// TestIntegration_ScanFile_EICAR tests that ClamAV detects the EICAR test file.
func TestIntegration_ScanFile_EICAR(t *testing.T) {
	scanner := setupIntegrationScanner(t)

	// Create EICAR test file.
	tmpDir := t.TempDir()
	eicarFile := filepath.Join(tmpDir, "eicar.txt")
	if err := os.WriteFile(eicarFile, []byte(eicarTestString), 0o644); err != nil {
		t.Fatalf("Failed to create EICAR file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := scanner.ScanFile(ctx, eicarFile)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	// Verify detection.
	if result.Status != types.ScanStatusInfected {
		t.Errorf("Status = %v, want %v", result.Status, types.ScanStatusInfected)
	}

	if !strings.Contains(strings.ToLower(result.Detection), "eicar") {
		t.Errorf("Detection = %q, should contain 'eicar'", result.Detection)
	}

	// Verify metadata.
	if result.FileHash == "" {
		t.Error("FileHash should not be empty")
	}
	if result.FileSize != int64(len(eicarTestString)) {
		t.Errorf("FileSize = %d, want %d", result.FileSize, len(eicarTestString))
	}
	if result.ScanTimeMs <= 0 {
		t.Error("ScanTimeMs should be positive")
	}

	t.Logf("EICAR detected: %s (severity: %s)", result.Detection, result.Severity)
}

// TestIntegration_ScanFile_Clean tests that clean files are not flagged.
func TestIntegration_ScanFile_Clean(t *testing.T) {
	scanner := setupIntegrationScanner(t)

	// Create clean test file.
	tmpDir := t.TempDir()
	cleanFile := filepath.Join(tmpDir, "clean.txt")
	content := "This is a perfectly clean file with no malware whatsoever."
	if err := os.WriteFile(cleanFile, []byte(content), 0o644); err != nil {
		t.Fatalf("Failed to create clean file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := scanner.ScanFile(ctx, cleanFile)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if result.Status != types.ScanStatusClean {
		t.Errorf("Status = %v, want %v", result.Status, types.ScanStatusClean)
	}

	if result.Detection != "" {
		t.Errorf("Detection = %q, want empty for clean file", result.Detection)
	}

	t.Logf("Clean file scanned in %.2fms", result.ScanTimeMs)
}

// TestIntegration_ScanDir tests directory scanning.
func TestIntegration_ScanDir(t *testing.T) {
	scanner := setupIntegrationScanner(t)

	// Create directory with mixed files.
	tmpDir := t.TempDir()

	// Clean files.
	os.WriteFile(filepath.Join(tmpDir, "clean1.txt"), []byte("clean content 1"), 0o644)
	os.WriteFile(filepath.Join(tmpDir, "clean2.txt"), []byte("clean content 2"), 0o644)

	// EICAR file.
	os.WriteFile(filepath.Join(tmpDir, "malware.txt"), []byte(eicarTestString), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	results, err := scanner.ScanDir(ctx, tmpDir, false)
	if err != nil {
		t.Fatalf("ScanDir() error = %v", err)
	}

	if len(results) != 3 {
		t.Errorf("Scanned %d files, want 3", len(results))
	}

	var clean, infected int
	for _, r := range results {
		switch r.Status {
		case types.ScanStatusClean:
			clean++
		case types.ScanStatusInfected:
			infected++
		}
	}

	if clean != 2 {
		t.Errorf("Clean files = %d, want 2", clean)
	}
	if infected != 1 {
		t.Errorf("Infected files = %d, want 1", infected)
	}

	t.Logf("Directory scan: %d clean, %d infected", clean, infected)
}

// TestIntegration_ScanDir_Recursive tests recursive directory scanning.
func TestIntegration_ScanDir_Recursive(t *testing.T) {
	scanner := setupIntegrationScanner(t)

	// Create nested directory structure.
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	os.MkdirAll(subDir, 0o755)

	// Files in root.
	os.WriteFile(filepath.Join(tmpDir, "root.txt"), []byte("root content"), 0o644)

	// Files in subdir.
	os.WriteFile(filepath.Join(subDir, "sub.txt"), []byte("sub content"), 0o644)
	os.WriteFile(filepath.Join(subDir, "eicar.txt"), []byte(eicarTestString), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Non-recursive should only scan root.
	nonRecursive, _ := scanner.ScanDir(ctx, tmpDir, false)
	if len(nonRecursive) != 1 {
		t.Errorf("Non-recursive scan: %d files, want 1", len(nonRecursive))
	}

	// Recursive should scan all.
	recursive, err := scanner.ScanDir(ctx, tmpDir, true)
	if err != nil {
		t.Fatalf("ScanDir(recursive) error = %v", err)
	}

	if len(recursive) != 3 {
		t.Errorf("Recursive scan: %d files, want 3", len(recursive))
	}

	t.Logf("Recursive scan found %d files", len(recursive))
}

// TestIntegration_ToSignature tests that infected results convert to signatures.
func TestIntegration_ToSignature(t *testing.T) {
	scanner := setupIntegrationScanner(t)

	// Create EICAR file.
	tmpDir := t.TempDir()
	eicarFile := filepath.Join(tmpDir, "eicar.txt")
	os.WriteFile(eicarFile, []byte(eicarTestString), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, _ := scanner.ScanFile(ctx, eicarFile)

	// Convert to signature.
	sig := result.ToSignature()
	if sig == nil {
		t.Fatal("ToSignature() returned nil for infected result")
	}

	if sig.SHA256 == "" {
		t.Error("Signature SHA256 should not be empty")
	}
	if sig.DetectionName == "" {
		t.Error("Signature DetectionName should not be empty")
	}
	if sig.Source != "clamav-scan" {
		t.Errorf("Signature Source = %q, want %q", sig.Source, "clamav-scan")
	}

	t.Logf("Signature: %s -> %s", sig.SHA256[:16]+"...", sig.DetectionName)
}

// TestIntegration_Ping tests scanner availability check.
func TestIntegration_Ping(t *testing.T) {
	scanner := setupIntegrationScanner(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := scanner.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
}

// TestIntegration_Version tests version retrieval.
func TestIntegration_Version(t *testing.T) {
	scanner := setupIntegrationScanner(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	version, err := scanner.Version(ctx)
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}

	if version == "" {
		t.Error("Version() returned empty string")
	}

	t.Logf("ClamAV version: %s", version)
}

// setupIntegrationScanner creates a scanner for integration tests.
// Skips the test if clamscan is not available.
func setupIntegrationScanner(t *testing.T) *ClamAVScanner {
	t.Helper()

	// Check if clamscan is available.
	paths := []string{
		"/usr/bin/clamscan",
		"/usr/local/bin/clamscan",
		"/opt/homebrew/bin/clamscan",
	}

	var binaryPath string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			binaryPath = p
			break
		}
	}

	if binaryPath == "" {
		t.Skip("clamscan not found, skipping integration test")
	}

	cfg := &config.ClamAVConfig{
		Mode:    "clamscan",
		Binary:  binaryPath,
		Timeout: 5 * time.Minute,
	}

	return NewClamAVScanner(cfg)
}
