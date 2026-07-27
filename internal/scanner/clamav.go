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

	"github.com/hikmaai-io/hikmaai-argus/internal/config"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
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
	fileSize := fileInfo.Size()

	// Check file size limit.
	if s.config.MaxFileSize > 0 && fileSize > s.config.MaxFileSize {
		return types.NewErrorScanResult(path, fmt.Sprintf("file too large: %d bytes (max: %d)", fileSize, s.config.MaxFileSize)).
			WithFileInfo(fileSize, ""), nil
	}

	// Calculate file hash.
	fileHash, err := hashFile(path)
	if err != nil {
		return types.NewErrorScanResult(path, fmt.Sprintf("hash failed: %v", err)).
			WithFileInfo(fileSize, ""), nil
	}

	// Scan based on mode.
	var result *types.ScanResult
	switch s.Mode() {
	case "clamd":
		result, err = s.scanWithClamd(ctx, path, fileHash, fileSize)
	default:
		result, err = s.scanWithClamscan(ctx, path, fileHash, fileSize)
	}

	if err != nil {
		return types.NewErrorScanResult(path, err.Error()).
			WithFileInfo(fileSize, fileHash), nil
	}

	// Add scan duration.
	elapsed := time.Since(start)
	result.ScanTimeMs = float64(elapsed.Milliseconds())

	return result, nil
}

// scanWithClamscan uses the clamscan binary to scan a file.
func (s *ClamAVScanner) scanWithClamscan(ctx context.Context, path, fileHash string, fileSize int64) (*types.ScanResult, error) {
	args := s.buildClamscanArgs(path)
	output, err := s.runClamscan(ctx, args)
	if err != nil {
		return nil, err
	}

	// Parse the output.
	result, err := parseClamscanOutput(path, output)
	if err != nil {
		return nil, fmt.Errorf("parsing output: %w", err)
	}

	result.FileHash = fileHash
	result.FileSize = fileSize

	return result, nil
}

func (s *ClamAVScanner) runClamscan(ctx context.Context, args []string) (string, error) {
	binary := s.config.Binary
	if binary == "" {
		binary = "clamscan"
	}

	cmdCtx := ctx
	if s.config.Timeout > 0 {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, s.config.Timeout)
		defer cancel()
	}

	output, err := exec.CommandContext(cmdCtx, binary, args...).CombinedOutput()
	if cmdCtx.Err() != nil {
		return string(output), fmt.Errorf("scan timeout: %w", cmdCtx.Err())
	}
	if err == nil {
		return string(output), nil
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return string(output), fmt.Errorf("exec failed: %w", err)
	}
	if exitErr.ExitCode() == 1 {
		return string(output), nil
	}
	return string(output), fmt.Errorf("clamscan error: %s", string(output))
}

// scanWithClamd uses the clamd daemon to scan a file.
func (s *ClamAVScanner) scanWithClamd(ctx context.Context, path, fileHash string, fileSize int64) (*types.ScanResult, error) {
	// TODO: Implement clamd scanning using baruwa-enterprise/clamd.
	// For now, fall back to clamscan.
	return s.scanWithClamscan(ctx, path, fileHash, fileSize)
}

// buildClamscanArgs builds the command-line arguments for clamscan.
func (s *ClamAVScanner) buildClamscanArgs(path string) []string {
	args := s.buildClamscanBaseArgs()
	return append(args, path)
}

func (s *ClamAVScanner) buildClamscanDirArgs(path string, recursive bool) []string {
	args := s.buildClamscanBaseArgs()
	if recursive {
		args = append(args, "--recursive")
	}
	return append(args, path)
}

func (s *ClamAVScanner) buildClamscanBaseArgs() []string {
	args := []string{}

	// Add database directory if specified.
	if s.config.DatabaseDir != "" {
		args = append(args, "--database", s.config.DatabaseDir)
	}

	// Enable recursive archive scanning (scans inside nested zips).
	// This is essential for detecting malware in nested archives like eicar_com2.zip.
	args = append(args,
		"--scan-archive=yes",  // Scan inside archives (default, but explicit)
		"--max-recursion=10",  // Allow nested archive scanning (default is 17)
		"--max-files=10000",   // Max files to scan in archive
		"--max-scansize=100M", // Max data to scan in archive
		"--max-filesize=100M", // Max file size to scan
	)

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

	results := parseClamscanResults(output)
	for _, result := range results {
		if result.FilePath == filePath {
			return result, nil
		}
	}
	if len(results) > 0 {
		return results[0], nil
	}
	return nil, fmt.Errorf("no file result in clamscan output")
}

func parseClamscanResults(output string) []*types.ScanResult {
	engineVersion := extractEngineVersion(output)
	scannedAt := time.Now().UTC()
	results := make([]*types.ScanResult, 0)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "---") {
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			continue
		}
		filePath := parts[0]
		resultPart := strings.TrimSpace(parts[1])

		result := &types.ScanResult{
			FilePath:      filePath,
			Engine:        "clamav",
			EngineVersion: engineVersion,
			ScannedAt:     scannedAt,
		}

		switch {
		case strings.HasSuffix(resultPart, " FOUND"):
			detection := strings.TrimSuffix(resultPart, " FOUND")
			result.Status = types.ScanStatusInfected
			result.Detection = detection
			result.ThreatType = types.ThreatTypeFromDetection(detection)
			result.Severity = types.SeverityFromDetection(detection)
		case strings.HasSuffix(resultPart, " ERROR"),
			strings.Contains(resultPart, "ERROR"):
			result.Status = types.ScanStatusError
			result.Error = resultPart
		case resultPart == "OK":
			result.Status = types.ScanStatusClean
		default:
			continue
		}
		results = append(results, result)
	}

	return results
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
	if s.Mode() == "clamscan" {
		return s.scanDirWithClamscan(ctx, path, recursive)
	}
	return s.scanDirFileByFile(ctx, path, recursive)
}

func (s *ClamAVScanner) scanDirWithClamscan(ctx context.Context, path string, recursive bool) ([]*types.ScanResult, error) {
	start := time.Now()
	output, err := s.runClamscan(ctx, s.buildClamscanDirArgs(path, recursive))
	if err != nil {
		return nil, err
	}

	results := parseClamscanResults(output)
	if len(results) == 0 {
		return nil, fmt.Errorf("no file results in clamscan output")
	}

	elapsedMs := float64(time.Since(start).Milliseconds())
	for _, result := range results {
		info, statErr := os.Stat(result.FilePath)
		if statErr == nil {
			result.FileSize = info.Size()
		}
		if result.Status == types.ScanStatusInfected {
			fileHash, hashErr := hashFile(result.FilePath)
			if hashErr == nil {
				result.FileHash = fileHash
			}
		}
		result.ScanTimeMs = elapsedMs
	}
	return results, nil
}

func (s *ClamAVScanner) scanDirFileByFile(ctx context.Context, path string, recursive bool) ([]*types.ScanResult, error) {
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
