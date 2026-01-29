// ABOUTME: Scanner orchestrates the Trivy Twirp workflow for dependency scanning
// ABOUTME: Handles caching, blob/artifact creation, and result aggregation

package trivy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

// ScannerConfig holds configuration for the Scanner.
type ScannerConfig struct {
	// ServerURL is the base URL of the Trivy server.
	ServerURL string

	// Timeout for scan operations.
	Timeout time.Duration

	// Cache for per-package vulnerability results.
	Cache *Cache

	// Logger for scan operations.
	Logger *slog.Logger
}

// Scanner orchestrates vulnerability scanning via Trivy server.
type Scanner struct {
	client *Client
	cache  *Cache
	logger *slog.Logger
}

// NewScanner creates a new Scanner with the given configuration.
func NewScanner(cfg ScannerConfig) *Scanner {
	client := NewClient(ClientConfig{
		ServerURL: cfg.ServerURL,
		Timeout:   cfg.Timeout,
	})

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Scanner{
		client: client,
		cache:  cfg.Cache,
		logger: logger,
	}
}

// ScanPackages scans the given packages for vulnerabilities.
// If severityFilter is non-empty, only vulnerabilities matching those severities are returned.
func (s *Scanner) ScanPackages(ctx context.Context, packages []Package, severityFilter []string) (*ScanResult, error) {
	if len(packages) == 0 {
		return nil, errors.New("at least one package is required")
	}

	startTime := time.Now()

	// Check cache for existing results
	var cachedVulns []Vulnerability
	var uncachedPackages []Package

	if s.cache != nil {
		cached, uncached := s.cache.GetMultiple(ctx, packages)
		uncachedPackages = uncached

		// Collect cached vulnerabilities
		for _, vulns := range cached {
			cachedVulns = append(cachedVulns, vulns...)
		}

		s.logger.Debug("cache check",
			slog.Int("cached", len(packages)-len(uncached)),
			slog.Int("uncached", len(uncached)),
		)
	} else {
		uncachedPackages = packages
	}

	// If all packages are cached, return aggregated result
	if len(uncachedPackages) == 0 {
		result := &ScanResult{
			Summary:         NewScanSummary(cachedVulns, len(packages)),
			Vulnerabilities: cachedVulns,
			ScannedAt:       time.Now(),
			ScanTimeMs:      float64(time.Since(startTime).Milliseconds()),
		}

		if len(severityFilter) > 0 {
			filtered := result.FilterBySeverity(severityFilter)
			return &filtered, nil
		}
		return result, nil
	}

	// Scan uncached packages via Trivy
	scannedVulns, err := s.scanViaTrivy(ctx, uncachedPackages)
	if err != nil {
		return nil, err
	}

	// Update cache with new results
	if s.cache != nil {
		s.cacheResults(ctx, uncachedPackages, scannedVulns)
	}

	// Combine cached and scanned vulnerabilities
	allVulns := append(cachedVulns, scannedVulns...)

	result := &ScanResult{
		Summary:         NewScanSummary(allVulns, len(packages)),
		Vulnerabilities: allVulns,
		ScannedAt:       time.Now(),
		ScanTimeMs:      float64(time.Since(startTime).Milliseconds()),
	}

	// Apply severity filter if specified
	if len(severityFilter) > 0 {
		filtered := result.FilterBySeverity(severityFilter)
		return &filtered, nil
	}

	return result, nil
}

// scanViaTrivy performs the full Trivy Twirp workflow.
func (s *Scanner) scanViaTrivy(ctx context.Context, packages []Package) ([]Vulnerability, error) {
	// Generate IDs
	blobID := generateBlobID(packages)
	artifactID := generateArtifactID(blobID)

	s.logger.Debug("starting trivy scan",
		slog.String("blob_id", blobID),
		slog.String("artifact_id", artifactID),
		slog.Int("packages", len(packages)),
	)

	// Step 1: PutBlob
	blobReq := TwirpPutBlobRequest{
		DiffID: blobID,
		BlobInfo: TwirpBlobInfo{
			SchemaVersion: 2,
			OS:            TwirpOSInfo{Family: "none"},
			Packages:      convertPackages(packages),
		},
	}

	if err := s.client.PutBlob(ctx, blobReq); err != nil {
		return nil, fmt.Errorf("failed to put blob: %w", err)
	}

	// Step 2: PutArtifact
	artifactReq := TwirpPutArtifactRequest{
		ArtifactID: artifactID,
		ArtifactInfo: TwirpArtifactInfo{
			SchemaVersion: 1,
			Architecture:  "",
			Created:       time.Now(),
			OS:            TwirpOSInfo{Family: "none"},
		},
	}

	if err := s.client.PutArtifact(ctx, artifactReq); err != nil {
		return nil, fmt.Errorf("failed to put artifact: %w", err)
	}

	// Step 3: Scan
	scanReq := TwirpScanRequest{
		Target:     "dependency-scan",
		ArtifactID: artifactID,
		BlobIDs:    []string{blobID},
		Options: TwirpScanOptions{
			Scanners: []string{"vuln"},
			PkgTypes: collectEcosystems(packages),
		},
	}

	scanResp, err := s.client.Scan(ctx, scanReq)
	if err != nil {
		return nil, fmt.Errorf("failed to scan: %w", err)
	}

	// Convert Twirp results to our Vulnerability type
	var vulns []Vulnerability
	for _, result := range scanResp.Results {
		ecosystem := result.Type
		if ecosystem == "" {
			ecosystem = "unknown"
		}
		for _, tv := range result.Vulnerabilities {
			vulns = append(vulns, tv.ToVulnerability(ecosystem))
		}
	}

	s.logger.Debug("trivy scan complete",
		slog.Int("vulnerabilities", len(vulns)),
	)

	return vulns, nil
}

// cacheResults stores scan results in cache, grouped by package.
func (s *Scanner) cacheResults(ctx context.Context, packages []Package, vulns []Vulnerability) {
	// Group vulnerabilities by package
	vulnsByPkg := make(map[string][]Vulnerability)
	for _, v := range vulns {
		key := fmt.Sprintf("%s:%s", v.Package, v.Version)
		vulnsByPkg[key] = append(vulnsByPkg[key], v)
	}

	// Cache each package's vulnerabilities
	for _, pkg := range packages {
		key := fmt.Sprintf("%s:%s", pkg.Name, pkg.Version)
		pkgVulns := vulnsByPkg[key]
		if pkgVulns == nil {
			pkgVulns = []Vulnerability{} // Clean package
		}

		if err := s.cache.Set(ctx, pkg, pkgVulns); err != nil {
			s.logger.Warn("failed to cache package vulnerabilities",
				slog.String("package", pkg.Name),
				slog.String("version", pkg.Version),
				slog.String("error", err.Error()),
			)
		}
	}
}

// generateBlobID creates a deterministic blob ID from the package list.
func generateBlobID(packages []Package) string {
	// Sort packages for deterministic hashing
	sorted := make([]Package, len(packages))
	copy(sorted, packages)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Ecosystem != sorted[j].Ecosystem {
			return sorted[i].Ecosystem < sorted[j].Ecosystem
		}
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Version < sorted[j].Version
	})

	// Create hash from sorted package list
	h := sha256.New()
	for _, pkg := range sorted {
		h.Write([]byte(pkg.Ecosystem))
		h.Write([]byte(":"))
		h.Write([]byte(pkg.Name))
		h.Write([]byte(":"))
		h.Write([]byte(pkg.Version))
		h.Write([]byte("\n"))
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// generateArtifactID creates an artifact ID from the blob ID.
func generateArtifactID(blobID string) string {
	h := sha256.New()
	h.Write([]byte("artifact:"))
	h.Write([]byte(blobID))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// convertPackages converts our Package type to Twirp format.
func convertPackages(packages []Package) []TwirpPackageInfo {
	result := make([]TwirpPackageInfo, len(packages))
	for i, pkg := range packages {
		result[i] = TwirpPackageInfo{
			Name:    pkg.Name,
			Version: pkg.Version,
			SrcName: pkg.SrcName,
		}
	}
	return result
}

// collectEcosystems returns unique ecosystems from the package list.
func collectEcosystems(packages []Package) []string {
	seen := make(map[string]bool)
	var result []string

	for _, pkg := range packages {
		if !seen[pkg.Ecosystem] {
			seen[pkg.Ecosystem] = true
			result = append(result, pkg.Ecosystem)
		}
	}

	return result
}

// Client returns the underlying Trivy client.
func (s *Scanner) Client() *Client {
	return s.client
}
