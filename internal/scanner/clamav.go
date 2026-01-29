// ABOUTME: ClamAV scanner with dual mode support (clamscan binary and clamd daemon)
// ABOUTME: Provides file scanning using ClamAV for malware detection

package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hikmaai-io/hikma-av/internal/config"
	"github.com/hikmaai-io/hikma-av/internal/types"
)

// ClamAVScanner provides malware scanning using ClamAV.
type ClamAVScanner struct {
	config *config.ClamAVConfig
}

// NewClamAVScanner creates a new ClamAV scanner.
func NewClamAVScanner(cfg *config.ClamAVConfig) *ClamAVScanner {
	return &ClamAVScanner{
		config: cfg,
	}
}

// Mode returns the scanner mode ("clamscan" or "clamd").
func (s *ClamAVScanner) Mode() string {
	if s.config.Mode == "" {
		return "clamscan"
	}
	return s.config.Mode
}

// ScanFile scans a single file for malware.
func (s *ClamAVScanner) ScanFile(ctx context.Context, path string) (*types.ScanResult, error) {
	start := time.Now()

	// Get file info for hash and size.
	fileInfo, err := os.Stat(path)
	if err != nil {
		return types.NewErrorScanResult(path, fmt.Sprintf("stat failed: %v", err)), nil
	}

	// Check file size limit.
	if s.config.MaxFileSize > 0 && fileInfo.Size() > s.config.MaxFileSize {
		return types.NewErrorScanResult(path, fmt.Sprintf("file too large: %d bytes (max: %d)", fileInfo.Size(), s.config.MaxFileSize)), nil
	}

	// Calculate file hash.
	fileHash, err := hashFile(path)
	if err != nil {
		return types.NewErrorScanResult(path, fmt.Sprintf("hash failed: %v", err)), nil
	}

	// Scan based on mode.
	var result *types.ScanResult
	switch s.Mode() {
	case "clamd":
		result, err = s.scanWithClamd(ctx, path, fileHash, fileInfo.Size())
	default:
		result, err = s.scanWithClamscan(ctx, path, fileHash, fileInfo.Size())
	}

	if err != nil {
		return types.NewErrorScanResult(path, err.Error()), nil
	}

	// Add scan duration.
	elapsed := time.Since(start)
	result.ScanTimeMs = float64(elapsed.Milliseconds())

	return result, nil
}

// scanWithClamscan uses the clamscan binary to scan a file.
func (s *ClamAVScanner) scanWithClamscan(ctx context.Context, path, fileHash string, fileSize int64) (*types.ScanResult, error) {
	binary := s.config.Binary
	if binary == "" {
		binary = "clamscan"
	}

	args := s.buildClamscanArgs(path)

	// Create command with context and timeout.
	cmdCtx := ctx
	if s.config.Timeout > 0 {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, s.config.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(cmdCtx, binary, args...)

	// Capture output.
	output, err := cmd.CombinedOutput()

	// clamscan returns exit code 1 for infections, which is not an error.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 = virus found, 2 = error.
			if exitErr.ExitCode() == 2 {
				return nil, fmt.Errorf("clamscan error: %s", string(output))
			}
		} else if cmdCtx.Err() != nil {
			return nil, fmt.Errorf("scan timeout: %w", cmdCtx.Err())
		}
	}

	// Parse the output.
	result, err := parseClamscanOutput(path, string(output))
	if err != nil {
		return nil, fmt.Errorf("parsing output: %w", err)
	}

	result.FileHash = fileHash
	result.FileSize = fileSize

	return result, nil
}

// scanWithClamd uses the clamd daemon to scan a file.
func (s *ClamAVScanner) scanWithClamd(ctx context.Context, path, fileHash string, fileSize int64) (*types.ScanResult, error) {
	// TODO: Implement clamd scanning using baruwa-enterprise/clamd.
	// For now, fall back to clamscan.
	return s.scanWithClamscan(ctx, path, fileHash, fileSize)
}

// buildClamscanArgs builds the command-line arguments for clamscan.
func (s *ClamAVScanner) buildClamscanArgs(path string) []string {
	args := []string{}

	// Add database directory if specified.
	if s.config.DatabaseDir != "" {
		args = append(args, "--database", s.config.DatabaseDir)
	}

	// Add the file path.
	args = append(args, path)

	return args
}

// Version returns the ClamAV engine version.
func (s *ClamAVScanner) Version(ctx context.Context) (string, error) {
	binary := s.config.Binary
	if binary == "" {
		binary = "clamscan"
	}

	cmd := exec.CommandContext(ctx, binary, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("getting version: %w", err)
	}

	// Parse version from output like "ClamAV 0.104.2/26789/..."
	version := strings.TrimSpace(string(output))
	parts := strings.Split(version, "/")
	if len(parts) > 0 {
		return strings.TrimPrefix(parts[0], "ClamAV "), nil
	}

	return version, nil
}

// Ping checks if the scanner is available.
func (s *ClamAVScanner) Ping(ctx context.Context) error {
	_, err := s.Version(ctx)
	return err
}

// parseClamscanOutput parses the output from clamscan.
func parseClamscanOutput(filePath, output string) (*types.ScanResult, error) {
	if output == "" {
		return nil, fmt.Errorf("empty clamscan output")
	}

	result := &types.ScanResult{
		FilePath:  filePath,
		Engine:    "clamav",
		ScannedAt: time.Now().UTC(),
	}

	// Extract engine version from summary.
	result.EngineVersion = extractEngineVersion(output)

	// Parse line by line looking for file result.
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and summary section.
		if line == "" || strings.HasPrefix(line, "---") {
			continue
		}

		// Look for file scan result lines.
		// Format: /path/to/file: RESULT
		if strings.Contains(line, ": ") {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) != 2 {
				continue
			}

			resultPart := strings.TrimSpace(parts[1])

			// Check for FOUND (infection).
			if strings.HasSuffix(resultPart, " FOUND") {
				detection := strings.TrimSuffix(resultPart, " FOUND")
				result.Status = types.ScanStatusInfected
				result.Detection = detection
				result.ThreatType = types.ThreatTypeFromDetection(detection)
				result.Severity = types.SeverityFromDetection(detection)
				return result, nil
			}

			// Check for ERROR.
			if strings.HasSuffix(resultPart, " ERROR") || strings.Contains(resultPart, "ERROR") {
				result.Status = types.ScanStatusError
				result.Error = resultPart
				return result, nil
			}

			// Check for OK (clean).
			if resultPart == "OK" {
				result.Status = types.ScanStatusClean
				return result, nil
			}
		}
	}

	// Default to clean if no detection found.
	result.Status = types.ScanStatusClean
	return result, nil
}

// extractEngineVersion extracts the engine version from clamscan output.
func extractEngineVersion(output string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Engine version:") {
			version := strings.TrimPrefix(line, "Engine version:")
			return strings.TrimSpace(version)
		}
	}
	return ""
}

// hashFile calculates the SHA256 hash of a file.
func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// ScanDir scans a directory for malware.
func (s *ClamAVScanner) ScanDir(ctx context.Context, path string, recursive bool) ([]*types.ScanResult, error) {
	var results []*types.ScanResult

	walkFn := func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors.
		}

		// Skip directories.
		if info.IsDir() {
			if !recursive && filePath != path {
				return filepath.SkipDir
			}
			return nil
		}

		// Check context.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Scan the file.
		result, err := s.ScanFile(ctx, filePath)
		if err != nil {
			result = types.NewErrorScanResult(filePath, err.Error())
		}
		results = append(results, result)

		return nil
	}

	if err := filepath.Walk(path, walkFn); err != nil {
		return results, err
	}

	return results, nil
}
