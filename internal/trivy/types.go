// ABOUTME: Type definitions for Trivy dependency vulnerability scanner
// ABOUTME: Includes package types, Twirp protocol types, and scan result types

package trivy

import (
	"errors"
	"fmt"
	"time"
)

// Ecosystem constants for supported package managers.
const (
	EcosystemPip      = "pip"
	EcosystemNpm      = "npm"
	EcosystemGomod    = "gomod"
	EcosystemCargo    = "cargo"
	EcosystemComposer = "composer"
	EcosystemMaven    = "maven"
	EcosystemNuget    = "nuget"
	EcosystemRubygems = "rubygems"
)

// validEcosystems is the set of supported package ecosystems.
var validEcosystems = map[string]bool{
	EcosystemPip:      true,
	EcosystemNpm:      true,
	EcosystemGomod:    true,
	EcosystemCargo:    true,
	EcosystemComposer: true,
	EcosystemMaven:    true,
	EcosystemNuget:    true,
	EcosystemRubygems: true,
}

// IsValidEcosystem returns true if the ecosystem is supported.
func IsValidEcosystem(ecosystem string) bool {
	return validEcosystems[ecosystem]
}

// Severity constants for vulnerability classification.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

// validSeverities is the set of valid severity levels.
var validSeverities = map[string]bool{
	SeverityCritical: true,
	SeverityHigh:     true,
	SeverityMedium:   true,
	SeverityLow:      true,
	SeverityUnknown:  true,
}

// IsValidSeverity returns true if the severity is valid.
func IsValidSeverity(severity string) bool {
	return validSeverities[severity]
}

// Package represents a dependency to scan.
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	SrcName   string `json:"src_name,omitempty"`
}

// Validate checks that the package has all required fields and a valid ecosystem.
func (p Package) Validate() error {
	if p.Name == "" {
		return errors.New("package name is required")
	}
	if p.Version == "" {
		return errors.New("package version is required")
	}
	if p.Ecosystem == "" {
		return errors.New("package ecosystem is required")
	}
	if !IsValidEcosystem(p.Ecosystem) {
		return fmt.Errorf("unsupported ecosystem: %s", p.Ecosystem)
	}
	return nil
}

// CacheKey returns the cache key for this package.
// Format: trivy:pkg:<ecosystem>:<name>:<version>
func (p Package) CacheKey() string {
	return fmt.Sprintf("trivy:pkg:%s:%s:%s", p.Ecosystem, p.Name, p.Version)
}

// ScanRequest is the API request for dependency scanning.
type ScanRequest struct {
	Packages       []Package `json:"packages"`
	SeverityFilter []string  `json:"severity_filter,omitempty"`
	ScanSecrets    bool      `json:"scan_secrets,omitempty"`
}

// Validate checks that the request has valid packages and severity filters.
func (r ScanRequest) Validate() error {
	if len(r.Packages) == 0 {
		return errors.New("at least one package is required")
	}

	for i, pkg := range r.Packages {
		if err := pkg.Validate(); err != nil {
			return fmt.Errorf("package %d: %w", i, err)
		}
	}

	for _, sev := range r.SeverityFilter {
		if !IsValidSeverity(sev) {
			return fmt.Errorf("invalid severity filter: %s", sev)
		}
	}

	return nil
}

// Vulnerability represents a found vulnerability.
type Vulnerability struct {
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	Ecosystem    string   `json:"ecosystem"`
	CVEID        string   `json:"cve_id"`
	Severity     string   `json:"severity"`
	Title        string   `json:"title"`
	Description  string   `json:"description,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	References   []string `json:"references,omitempty"`
}

// MatchesSeverityFilter returns true if the vulnerability matches the severity filter.
// An empty or nil filter matches all severities.
func (v Vulnerability) MatchesSeverityFilter(filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, sev := range filter {
		if v.Severity == sev {
			return true
		}
	}
	return false
}

// ScanSummary provides counts by severity.
type ScanSummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	PackagesScanned      int `json:"packages_scanned"`
}

// NewScanSummary creates a summary from a list of vulnerabilities.
func NewScanSummary(vulns []Vulnerability, packagesScanned int) ScanSummary {
	summary := ScanSummary{
		TotalVulnerabilities: len(vulns),
		PackagesScanned:      packagesScanned,
	}

	for _, v := range vulns {
		switch v.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		}
	}

	return summary
}

// ScanResult is the result of a dependency scan.
type ScanResult struct {
	Summary         ScanSummary     `json:"summary"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	ScannedAt       time.Time       `json:"scanned_at"`
	ScanTimeMs      float64         `json:"scan_time_ms"`
}

// FilterBySeverity returns a new ScanResult with only vulnerabilities matching the filter.
func (r ScanResult) FilterBySeverity(filter []string) ScanResult {
	if len(filter) == 0 {
		return r
	}

	filtered := make([]Vulnerability, 0, len(r.Vulnerabilities))
	for _, v := range r.Vulnerabilities {
		if v.MatchesSeverityFilter(filter) {
			filtered = append(filtered, v)
		}
	}

	return ScanResult{
		Summary:         NewScanSummary(filtered, r.Summary.PackagesScanned),
		Vulnerabilities: filtered,
		ScannedAt:       r.ScannedAt,
		ScanTimeMs:      r.ScanTimeMs,
	}
}

// JobResponse is the response for async scan job submission.
type JobResponse struct {
	JobID   string `json:"job_id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// JobStatusResponse is the response for job status polling.
type JobStatusResponse struct {
	JobID           string          `json:"job_id"`
	Status          string          `json:"status"`
	Summary         *ScanSummary    `json:"summary,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	ScannedAt       *time.Time      `json:"scanned_at,omitempty"`
	Error           string          `json:"error,omitempty"`
}

// Twirp protocol types for communication with Trivy server.

// TwirpPackageInfo represents a package in the Twirp protocol.
type TwirpPackageInfo struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
	SrcName string `json:"SrcName,omitempty"`
}

// TwirpOSInfo represents OS information in the Twirp protocol.
type TwirpOSInfo struct {
	Family string `json:"Family"`
	Name   string `json:"Name,omitempty"`
}

// TwirpBlobInfo represents blob information for PutBlob request.
type TwirpBlobInfo struct {
	SchemaVersion int                `json:"SchemaVersion"`
	OS            TwirpOSInfo        `json:"OS"`
	Packages      []TwirpPackageInfo `json:"Packages,omitempty"`
}

// TwirpPutBlobRequest is the request body for PutBlob.
type TwirpPutBlobRequest struct {
	DiffID   string        `json:"diff_id"`
	BlobInfo TwirpBlobInfo `json:"blob_info"`
}

// TwirpArtifactInfo represents artifact information for PutArtifact request.
type TwirpArtifactInfo struct {
	SchemaVersion int         `json:"SchemaVersion"`
	Architecture  string      `json:"Architecture"`
	Created       time.Time   `json:"Created"`
	OS            TwirpOSInfo `json:"OS"`
}

// TwirpPutArtifactRequest is the request body for PutArtifact.
type TwirpPutArtifactRequest struct {
	ArtifactID   string            `json:"artifact_id"`
	ArtifactInfo TwirpArtifactInfo `json:"artifact_info"`
}

// TwirpScanOptions contains scan configuration.
type TwirpScanOptions struct {
	Scanners   []string `json:"Scanners"`
	PkgTypes   []string `json:"PkgTypes,omitempty"`
	Severities []string `json:"Severities,omitempty"`
}

// TwirpScanRequest is the request body for Scan.
type TwirpScanRequest struct {
	Target     string           `json:"target"`
	ArtifactID string           `json:"artifact_id"`
	BlobIDs    []string         `json:"blob_ids"`
	Options    TwirpScanOptions `json:"options"`
}

// TwirpVulnerability represents a vulnerability in the Twirp response.
type TwirpVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion,omitempty"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title,omitempty"`
	Description      string   `json:"Description,omitempty"`
	References       []string `json:"References,omitempty"`
	PkgType          string   `json:"PkgType,omitempty"`
}

// TwirpResult represents a result in the Twirp response.
type TwirpResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class,omitempty"`
	Type            string               `json:"Type,omitempty"`
	Vulnerabilities []TwirpVulnerability `json:"Vulnerabilities,omitempty"`
}

// TwirpScanResponse is the response from the Scan endpoint.
type TwirpScanResponse struct {
	Results []TwirpResult `json:"Results,omitempty"`
}

// ToVulnerability converts a Twirp vulnerability to our Vulnerability type.
func (tv TwirpVulnerability) ToVulnerability(ecosystem string) Vulnerability {
	return Vulnerability{
		Package:      tv.PkgName,
		Version:      tv.InstalledVersion,
		Ecosystem:    ecosystem,
		CVEID:        tv.VulnerabilityID,
		Severity:     tv.Severity,
		Title:        tv.Title,
		Description:  tv.Description,
		FixedVersion: tv.FixedVersion,
		References:   tv.References,
	}
}
