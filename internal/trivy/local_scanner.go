// ABOUTME: Local Trivy scanner that runs trivy CLI directly without a remote server
// ABOUTME: Supports filesystem scanning for vulnerabilities and secrets

package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// LocalScannerConfig holds configuration for the local Trivy scanner.
type LocalScannerConfig struct {
	// Binary is the path to the trivy binary (default: "trivy").
	Binary string

	// Timeout for scan operations.
	Timeout time.Duration

	// CacheDir is the directory for Trivy's cache (optional).
	CacheDir string

	// SkipDBUpdate skips updating the vulnerability database.
	SkipDBUpdate bool
}

// LocalScanner scans filesystems using the local trivy CLI.
type LocalScanner struct {
	binary       string
	timeout      time.Duration
	cacheDir     string
	skipDBUpdate bool
}

// NewLocalScanner creates a new LocalScanner with the given configuration.
func NewLocalScanner(cfg LocalScannerConfig) *LocalScanner {
	binary := cfg.Binary
	if binary == "" {
		binary = "trivy"
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	return &LocalScanner{
		binary:       binary,
		timeout:      timeout,
		cacheDir:     cfg.CacheDir,
		skipDBUpdate: cfg.SkipDBUpdate,
	}
}

// Ping checks if the trivy binary is available.
func (s *LocalScanner) Ping(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.binary, "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy not available: %w", err)
	}
	return nil
}

// TrivyJSONReport is the JSON output from trivy fs command.
type TrivyJSONReport struct {
	SchemaVersion int                 `json:"SchemaVersion"`
	CreatedAt     time.Time           `json:"CreatedAt"`
	ArtifactName  string              `json:"ArtifactName"`
	ArtifactType  string              `json:"ArtifactType"`
	Results       []TrivyJSONResult   `json:"Results"`
	Metadata      *TrivyJSONMetadata  `json:"Metadata,omitempty"`
}

// TrivyJSONMetadata contains metadata from the scan.
type TrivyJSONMetadata struct {
	OS *TrivyJSONOS `json:"OS,omitempty"`
}

// TrivyJSONOS contains OS information.
type TrivyJSONOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

// TrivyJSONResult is a result section in the JSON output.
type TrivyJSONResult struct {
	Target          string                  `json:"Target"`
	Class           string                  `json:"Class"`
	Type            string                  `json:"Type"`
	Packages        []TrivyJSONPackage      `json:"Packages,omitempty"`
	Vulnerabilities []TrivyJSONVulnItem     `json:"Vulnerabilities,omitempty"`
	Secrets         []TrivyJSONSecretItem   `json:"Secrets,omitempty"`
}

// TrivyJSONPackage is a package item in the JSON output.
type TrivyJSONPackage struct {
	ID      string `json:"ID"`
	Name    string `json:"Name"`
	Version string `json:"Version,omitempty"`
}

// TrivyJSONVulnItem is a vulnerability item in the JSON output.
type TrivyJSONVulnItem struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgID            string   `json:"PkgID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion,omitempty"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title,omitempty"`
	Description      string   `json:"Description,omitempty"`
	References       []string `json:"References,omitempty"`
	PkgType          string   `json:"PkgType,omitempty"`
}

// TrivyJSONSecretItem is a secret item in the JSON output.
type TrivyJSONSecretItem struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match,omitempty"`
}

// ScanFS scans a filesystem path for vulnerabilities and secrets.
func (s *LocalScanner) ScanFS(ctx context.Context, path string, opts ScanOptions) (*ScanResult, error) {
	startTime := time.Now()

	// Build command arguments.
	args := []string{
		"fs",
		"--format", "json",
		"--quiet",
	}

	// Add scanners.
	scanners := "vuln"
	if opts.ScanSecrets {
		scanners = "vuln,secret"
	}
	args = append(args, "--scanners", scanners)

	// Add severity filter.
	if len(opts.SeverityFilter) > 0 {
		severities := ""
		for i, sev := range opts.SeverityFilter {
			if i > 0 {
				severities += ","
			}
			severities += sev
		}
		args = append(args, "--severity", severities)
	}

	// Add cache options.
	if s.cacheDir != "" {
		args = append(args, "--cache-dir", s.cacheDir)
	}
	if s.skipDBUpdate {
		args = append(args, "--skip-db-update")
	}

	// Add target path.
	args = append(args, path)

	// Create context with timeout.
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Run trivy.
	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Check if it's a context timeout.
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("scan timed out after %v", s.timeout)
		}
		// Trivy returns non-zero exit code when vulnerabilities are found; that's OK.
		// Only fail if we got no output.
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("trivy scan failed: %w (stderr: %s)", err, stderr.String())
		}
	}

	// Parse JSON output.
	var report TrivyJSONReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}

	// Convert to our types.
	return s.convertReport(&report, startTime), nil
}

// convertReport converts a Trivy JSON report to our ScanResult.
func (s *LocalScanner) convertReport(report *TrivyJSONReport, startTime time.Time) *ScanResult {
	var vulns []Vulnerability
	var secrets []Secret
	packagesScanned := 0

	for _, result := range report.Results {
		ecosystem := mapTypeToEcosystem(result.Type)

		// Count packages from Packages field (more accurate).
		packagesScanned += len(result.Packages)

		// Convert vulnerabilities.
		for _, v := range result.Vulnerabilities {
			vulns = append(vulns, Vulnerability{
				Package:      v.PkgName,
				Version:      v.InstalledVersion,
				Ecosystem:    ecosystem,
				CVEID:        v.VulnerabilityID,
				Severity:     v.Severity,
				Title:        v.Title,
				Description:  v.Description,
				FixedVersion: v.FixedVersion,
				References:   v.References,
			})
		}

		// Convert secrets.
		for _, sec := range result.Secrets {
			secrets = append(secrets, Secret{
				RuleID:    sec.RuleID,
				Category:  sec.Category,
				Severity:  sec.Severity,
				Title:     sec.Title,
				Target:    result.Target,
				StartLine: sec.StartLine,
				EndLine:   sec.EndLine,
				Match:     sec.Match,
			})
		}
	}

	return &ScanResult{
		Summary:         NewScanSummary(vulns, packagesScanned),
		Vulnerabilities: vulns,
		Secrets:         secrets,
		SecretSummary:   NewSecretSummary(secrets),
		ScannedAt:       time.Now(),
		ScanTimeMs:      float64(time.Since(startTime).Milliseconds()),
	}
}

// mapTypeToEcosystem maps Trivy's type to our ecosystem constants.
func mapTypeToEcosystem(trivyType string) string {
	switch trivyType {
	case "pip", "pipenv", "poetry":
		return EcosystemPip
	case "npm", "yarn", "pnpm":
		return EcosystemNpm
	case "gomod":
		return EcosystemGomod
	case "cargo":
		return EcosystemCargo
	case "composer":
		return EcosystemComposer
	case "bundler", "gemspec":
		return EcosystemRubygems
	case "pom", "gradle":
		return EcosystemMaven
	case "nuget", "dotnet-core", "packages-lock":
		return EcosystemNuget
	default:
		if trivyType != "" {
			return trivyType
		}
		return "unknown"
	}
}

// ScanArchive scans an archive file by extracting it first.
// Returns the scan result and cleans up the extracted directory.
func (s *LocalScanner) ScanArchive(ctx context.Context, archivePath string, opts ScanOptions) (*ScanResult, error) {
	// Extract archive to temp directory.
	extractDir, err := ExtractArchive(archivePath)
	if err != nil {
		return nil, fmt.Errorf("extracting archive: %w", err)
	}
	defer os.RemoveAll(extractDir)

	return s.ScanFS(ctx, extractDir, opts)
}

// ScanPath scans either a directory or archive for vulnerabilities.
// Automatically detects if the path is an archive and extracts if needed.
func (s *LocalScanner) ScanPath(ctx context.Context, path string, opts ScanOptions) (*ScanResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("accessing path: %w", err)
	}

	if info.IsDir() {
		return s.ScanFS(ctx, path, opts)
	}

	// Check if it's an archive.
	if isArchive(path) {
		return s.ScanArchive(ctx, path, opts)
	}

	// Single file; scan directly.
	return s.ScanFS(ctx, path, opts)
}
