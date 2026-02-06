// ABOUTME: Tests for ClamAV scanner with dual mode support
// ABOUTME: Tests clamscan binary mode and result parsing

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

func TestNewClamAVScanner(t *testing.T) {
	t.Parallel()

	cfg := &config.ClamAVConfig{
		Mode:        "clamscan",
		Binary:      "clamscan",
		DatabaseDir: "/tmp/clamav",
		Timeout:     time.Minute,
	}

	scanner := NewClamAVScanner(cfg)
	if scanner == nil {
		t.Fatal("NewClamAVScanner() returned nil")
	}
}

func TestClamAVScanner_Mode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mode     string
		expected string
	}{
		{name: "clamscan mode", mode: "clamscan", expected: "clamscan"},
		{name: "clamd mode", mode: "clamd", expected: "clamd"},
		{name: "default mode", mode: "", expected: "clamscan"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.ClamAVConfig{Mode: tt.mode}
			scanner := NewClamAVScanner(cfg)

			if got := scanner.Mode(); got != tt.expected {
				t.Errorf("Mode() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseClamscanOutput_Clean(t *testing.T) {
	t.Parallel()

	output := `/path/to/file.txt: OK

----------- SCAN SUMMARY -----------
Known viruses: 8678127
Engine version: 0.104.2
Scanned files: 1
Infected files: 0
Data scanned: 0.00 MB
Data read: 0.00 MB`

	result, err := parseClamscanOutput("/path/to/file.txt", output)
	if err != nil {
		t.Fatalf("parseClamscanOutput() error = %v", err)
	}

	if result.Status != types.ScanStatusClean {
		t.Errorf("Status = %v, want %v", result.Status, types.ScanStatusClean)
	}
	if result.Detection != "" {
		t.Errorf("Detection = %q, want empty", result.Detection)
	}
	if result.EngineVersion != "0.104.2" {
		t.Errorf("EngineVersion = %q, want %q", result.EngineVersion, "0.104.2")
	}
}

func TestParseClamscanOutput_Infected(t *testing.T) {
	t.Parallel()

	output := `/path/to/eicar.txt: Eicar-Signature FOUND

----------- SCAN SUMMARY -----------
Known viruses: 8678127
Engine version: 0.104.2
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB`

	result, err := parseClamscanOutput("/path/to/eicar.txt", output)
	if err != nil {
		t.Fatalf("parseClamscanOutput() error = %v", err)
	}

	if result.Status != types.ScanStatusInfected {
		t.Errorf("Status = %v, want %v", result.Status, types.ScanStatusInfected)
	}
	if result.Detection != "Eicar-Signature" {
		t.Errorf("Detection = %q, want %q", result.Detection, "Eicar-Signature")
	}
}

func TestParseClamscanOutput_MultiWord_Detection(t *testing.T) {
	t.Parallel()

	output := `/path/to/malware.exe: Win.Trojan.Agent-123456 FOUND

----------- SCAN SUMMARY -----------
Infected files: 1`

	result, err := parseClamscanOutput("/path/to/malware.exe", output)
	if err != nil {
		t.Fatalf("parseClamscanOutput() error = %v", err)
	}

	if result.Status != types.ScanStatusInfected {
		t.Errorf("Status = %v, want %v", result.Status, types.ScanStatusInfected)
	}
	if result.Detection != "Win.Trojan.Agent-123456" {
		t.Errorf("Detection = %q, want %q", result.Detection, "Win.Trojan.Agent-123456")
	}
}

func TestParseClamscanOutput_Error(t *testing.T) {
	t.Parallel()

	output := `/path/to/file.txt: lstat() failed: No such file or directory. ERROR

----------- SCAN SUMMARY -----------
Infected files: 0`

	result, err := parseClamscanOutput("/path/to/file.txt", output)
	if err != nil {
		t.Fatalf("parseClamscanOutput() error = %v", err)
	}

	if result.Status != types.ScanStatusError {
		t.Errorf("Status = %v, want %v", result.Status, types.ScanStatusError)
	}
	if !strings.Contains(result.Error, "lstat() failed") {
		t.Errorf("Error = %q, should contain 'lstat() failed'", result.Error)
	}
}

func TestParseClamscanOutput_EmptyOutput(t *testing.T) {
	t.Parallel()

	_, err := parseClamscanOutput("/path/to/file.txt", "")
	if err == nil {
		t.Error("parseClamscanOutput() should error on empty output")
	}
}

func TestExtractEngineVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		output  string
		want    string
	}{
		{
			name:   "standard format",
			output: "Engine version: 0.104.2\nOther stuff",
			want:   "0.104.2",
		},
		{
			name:   "with extra spaces",
			output: "Engine version:  1.0.0 \n",
			want:   "1.0.0",
		},
		{
			name:   "no version",
			output: "No version info here",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := extractEngineVersion(tt.output); got != tt.want {
				t.Errorf("extractEngineVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClamAVScanner_BuildCommand(t *testing.T) {
	t.Parallel()

	cfg := &config.ClamAVConfig{
		Mode:        "clamscan",
		Binary:      "/usr/bin/clamscan",
		DatabaseDir: "/var/lib/clamav",
		Timeout:     2 * time.Minute,
	}

	scanner := NewClamAVScanner(cfg)
	args := scanner.buildClamscanArgs("/path/to/file.txt")

	// Check essential arguments.
	hasDatabase := false
	hasNoSummary := false
	hasInfected := false

	for i, arg := range args {
		if arg == "--database" || arg == "-d" {
			if i+1 < len(args) && args[i+1] == "/var/lib/clamav" {
				hasDatabase = true
			}
		}
		if arg == "--no-summary" {
			hasNoSummary = true
		}
		if arg == "--infected" {
			hasInfected = true
		}
	}

	if !hasDatabase {
		t.Error("Command should include --database flag")
	}
	if hasNoSummary {
		t.Error("Command should NOT include --no-summary (we parse the summary)")
	}
	if hasInfected {
		t.Error("Command should NOT include --infected (we want all results)")
	}

	// Last arg should be the file path.
	if args[len(args)-1] != "/path/to/file.txt" {
		t.Errorf("Last arg = %q, want file path", args[len(args)-1])
	}
}

// TestClamAVScanner_ScanFile_PreservesFileInfoOnError verifies that error results
// retain FileSize and FileHash when the scan command fails.
func TestClamAVScanner_ScanFile_PreservesFileInfoOnError(t *testing.T) {
	t.Parallel()

	// Create a real file so os.Stat and hashFile succeed.
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Use a non-existent binary to force an exec error.
	cfg := &config.ClamAVConfig{
		Mode:    "clamscan",
		Binary:  "/nonexistent/clamscan-binary",
		Timeout: 10 * time.Second,
	}

	scanner := NewClamAVScanner(cfg)
	ctx := context.Background()

	result, err := scanner.ScanFile(ctx, testFile)
	if err != nil {
		t.Fatalf("ScanFile() returned unexpected error: %v", err)
	}

	// The result should be an error status but still have file info.
	if result.Status != types.ScanStatusError {
		t.Errorf("Status = %v, want %v", result.Status, types.ScanStatusError)
	}
	if result.FileSize == 0 {
		t.Error("FileSize should be non-zero on error result")
	}
	if result.FileHash == "" {
		t.Error("FileHash should be non-empty on error result")
	}
}

// TestClamAVScanner_scanWithClamscan_BinaryNotFound verifies that a missing binary
// returns an error instead of falling through to parseClamscanOutput.
func TestClamAVScanner_scanWithClamscan_BinaryNotFound(t *testing.T) {
	t.Parallel()

	cfg := &config.ClamAVConfig{
		Mode:   "clamscan",
		Binary: "/nonexistent/clamscan-binary",
	}

	scanner := NewClamAVScanner(cfg)
	ctx := context.Background()

	_, err := scanner.scanWithClamscan(ctx, "/tmp/somefile.txt", "abc123", 1024)
	if err == nil {
		t.Fatal("scanWithClamscan() should return error for missing binary")
	}
	if !strings.Contains(err.Error(), "exec failed") {
		t.Errorf("error = %q, should contain 'exec failed'", err.Error())
	}
}

// TestClamAVScanner_ScanFile_Integration tests actual scanning if clamscan is available.
// Skip if clamscan is not installed.
func TestClamAVScanner_ScanFile_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if clamscan is available.
	if _, err := os.Stat("/usr/bin/clamscan"); os.IsNotExist(err) {
		if _, err := os.Stat("/usr/local/bin/clamscan"); os.IsNotExist(err) {
			if _, err := os.Stat("/opt/homebrew/bin/clamscan"); os.IsNotExist(err) {
				t.Skip("clamscan not found, skipping integration test")
			}
		}
	}

	// Create a clean test file.
	tmpDir := t.TempDir()
	cleanFile := filepath.Join(tmpDir, "clean.txt")
	if err := os.WriteFile(cleanFile, []byte("This is a clean file"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cfg := &config.ClamAVConfig{
		Mode:    "clamscan",
		Binary:  "clamscan",
		Timeout: 5 * time.Minute,
	}

	scanner := NewClamAVScanner(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := scanner.ScanFile(ctx, cleanFile)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if result.Status != types.ScanStatusClean {
		t.Errorf("Status = %v, want %v", result.Status, types.ScanStatusClean)
	}
}

// TestClamAVScanner_ScanFile_EICAR tests EICAR detection if clamscan is available.
func TestClamAVScanner_ScanFile_EICAR(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if clamscan is available.
	if _, err := os.Stat("/usr/bin/clamscan"); os.IsNotExist(err) {
		if _, err := os.Stat("/usr/local/bin/clamscan"); os.IsNotExist(err) {
			if _, err := os.Stat("/opt/homebrew/bin/clamscan"); os.IsNotExist(err) {
				t.Skip("clamscan not found, skipping integration test")
			}
		}
	}

	// Create EICAR test file.
	tmpDir := t.TempDir()
	eicarFile := filepath.Join(tmpDir, "eicar.txt")
	eicarContent := "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	if err := os.WriteFile(eicarFile, []byte(eicarContent), 0o644); err != nil {
		t.Fatalf("Failed to create EICAR file: %v", err)
	}

	cfg := &config.ClamAVConfig{
		Mode:    "clamscan",
		Binary:  "clamscan",
		Timeout: 5 * time.Minute,
	}

	scanner := NewClamAVScanner(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := scanner.ScanFile(ctx, eicarFile)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if result.Status != types.ScanStatusInfected {
		t.Errorf("Status = %v, want %v", result.Status, types.ScanStatusInfected)
	}
	if !strings.Contains(strings.ToLower(result.Detection), "eicar") {
		t.Errorf("Detection = %q, should contain 'eicar'", result.Detection)
	}
}
