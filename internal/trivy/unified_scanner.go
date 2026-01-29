// ABOUTME: Unified Trivy scanner with dual mode support (local binary and server)
// ABOUTME: Provides dependency scanning using Trivy for vulnerability and secret detection

package trivy

import (
	"context"
	"fmt"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/config"
)

// UnifiedScanner provides vulnerability scanning using Trivy.
// Supports both local (trivy CLI) and server (Twirp) modes.
type UnifiedScanner struct {
	config       *config.TrivyConfig
	localScanner *LocalScanner
	serverScanner *Scanner
}

// NewUnifiedScanner creates a new Trivy scanner based on configuration.
func NewUnifiedScanner(cfg *config.TrivyConfig) *UnifiedScanner {
	s := &UnifiedScanner{
		config: cfg,
	}

	// Initialize the appropriate scanner based on mode.
	switch s.Mode() {
	case "server":
		s.serverScanner = NewScanner(ScannerConfig{
			ServerURL: cfg.ServerURL,
			Timeout:   cfg.Timeout,
		})
	default:
		// local mode (default)
		s.localScanner = NewLocalScanner(LocalScannerConfig{
			Binary:       cfg.Binary,
			Timeout:      cfg.Timeout,
			CacheDir:     cfg.CacheDir,
			SkipDBUpdate: cfg.SkipDBUpdate,
		})
	}

	return s
}

// Mode returns the scanner mode ("local" or "server").
func (s *UnifiedScanner) Mode() string {
	if s.config.Mode == "" {
		return "local"
	}
	return s.config.Mode
}

// Ping checks if the scanner is available.
func (s *UnifiedScanner) Ping(ctx context.Context) error {
	switch s.Mode() {
	case "server":
		// For server mode, we don't have a ping; return nil.
		return nil
	default:
		return s.localScanner.Ping(ctx)
	}
}

// ScanPath scans a path (directory or archive) for vulnerabilities and secrets.
// This is the main entry point for combined scanning.
func (s *UnifiedScanner) ScanPath(ctx context.Context, path string, opts ScanOptions) (*ScanResult, error) {
	switch s.Mode() {
	case "server":
		return s.scanPathWithServer(ctx, path, opts)
	default:
		return s.localScanner.ScanPath(ctx, path, opts)
	}
}

// scanPathWithServer scans a path using the Trivy server mode.
// Extracts packages from manifests and sends to server for vulnerability lookup.
func (s *UnifiedScanner) scanPathWithServer(ctx context.Context, path string, opts ScanOptions) (*ScanResult, error) {
	// Extract packages from manifests.
	packages, err := ScanPathForPackages(path)
	if err != nil {
		return nil, fmt.Errorf("extracting packages from manifests: %w", err)
	}

	if len(packages) == 0 {
		// No packages found; return empty result.
		return &ScanResult{
			Summary:   ScanSummary{PackagesScanned: 0},
			ScannedAt: time.Now(),
		}, nil
	}

	return s.serverScanner.ScanPackagesWithOptions(ctx, packages, opts)
}

// ScanPackages scans the given packages for vulnerabilities (server mode only).
// For local mode, use ScanPath instead.
func (s *UnifiedScanner) ScanPackages(ctx context.Context, packages []Package, severityFilter []string) (*ScanResult, error) {
	if s.Mode() != "server" {
		return nil, fmt.Errorf("ScanPackages is only available in server mode; use ScanPath for local mode")
	}
	return s.serverScanner.ScanPackages(ctx, packages, severityFilter)
}

// ScanPackagesWithOptions scans packages with full options (server mode only).
func (s *UnifiedScanner) ScanPackagesWithOptions(ctx context.Context, packages []Package, opts ScanOptions) (*ScanResult, error) {
	if s.Mode() != "server" {
		return nil, fmt.Errorf("ScanPackagesWithOptions is only available in server mode; use ScanPath for local mode")
	}
	return s.serverScanner.ScanPackagesWithOptions(ctx, packages, opts)
}

// DefaultScanOptions returns scan options with HIGH/CRITICAL severity filter and secret scanning enabled.
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		SeverityFilter: []string{SeverityCritical, SeverityHigh},
		ScanSecrets:    true,
	}
}
