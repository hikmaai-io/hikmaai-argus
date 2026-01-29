// ABOUTME: ScanResult type for ClamAV file scanning results
// ABOUTME: Contains scan status, detection info, and severity mapping from ClamAV

package types

import (
	"strings"
	"time"
)

// ScanStatus represents the result of a ClamAV file scan.
type ScanStatus int

const (
	// ScanStatusClean indicates the file is clean (no malware detected).
	ScanStatusClean ScanStatus = iota
	// ScanStatusInfected indicates the file contains malware.
	ScanStatusInfected
	// ScanStatusError indicates an error occurred during scanning.
	ScanStatusError
)

// String returns the string representation of the scan status.
func (s ScanStatus) String() string {
	switch s {
	case ScanStatusClean:
		return "clean"
	case ScanStatusInfected:
		return "infected"
	case ScanStatusError:
		return "error"
	default:
		return "unknown"
	}
}

// IsInfected returns true if the status indicates malware was found.
func (s ScanStatus) IsInfected() bool {
	return s == ScanStatusInfected
}

// ScanResult represents the result of a ClamAV file scan.
type ScanResult struct {
	// File information.
	FilePath string `json:"file_path"`
	FileHash string `json:"file_hash"` // SHA256 of scanned file
	FileSize int64  `json:"file_size"`

	// Scan result.
	Status    ScanStatus `json:"status"`
	Detection string     `json:"detection,omitempty"` // ClamAV detection name

	// Threat classification.
	ThreatType ThreatType `json:"threat_type,omitempty"`
	Severity   Severity   `json:"severity,omitempty"`

	// Engine information.
	Engine        string `json:"engine"`
	EngineVersion string `json:"engine_version,omitempty"`

	// Metadata.
	ScanTimeMs float64   `json:"scan_time_ms,omitempty"`
	ScannedAt  time.Time `json:"scanned_at"`

	// Error information.
	Error string `json:"error,omitempty"`
}

// NewCleanScanResult creates a new ScanResult for a clean file.
func NewCleanScanResult(filePath, fileHash string, fileSize int64) *ScanResult {
	return &ScanResult{
		FilePath:  filePath,
		FileHash:  fileHash,
		FileSize:  fileSize,
		Status:    ScanStatusClean,
		Engine:    "clamav",
		ScannedAt: time.Now().UTC(),
	}
}

// NewInfectedScanResult creates a new ScanResult for an infected file.
func NewInfectedScanResult(filePath, fileHash string, fileSize int64, detection string) *ScanResult {
	return &ScanResult{
		FilePath:   filePath,
		FileHash:   fileHash,
		FileSize:   fileSize,
		Status:     ScanStatusInfected,
		Detection:  detection,
		ThreatType: ThreatTypeFromDetection(detection),
		Severity:   SeverityFromDetection(detection),
		Engine:     "clamav",
		ScannedAt:  time.Now().UTC(),
	}
}

// NewErrorScanResult creates a new ScanResult for a scan error.
func NewErrorScanResult(filePath, errMsg string) *ScanResult {
	return &ScanResult{
		FilePath:  filePath,
		Status:    ScanStatusError,
		Error:     errMsg,
		Engine:    "clamav",
		ScannedAt: time.Now().UTC(),
	}
}

// IsInfected returns true if the scan found malware.
func (r *ScanResult) IsInfected() bool {
	return r.Status.IsInfected()
}

// WithScanTime sets the scan duration and returns the result for chaining.
func (r *ScanResult) WithScanTime(ms float64) *ScanResult {
	r.ScanTimeMs = ms
	return r
}

// WithEngineVersion sets the ClamAV engine version and returns the result for chaining.
func (r *ScanResult) WithEngineVersion(version string) *ScanResult {
	r.EngineVersion = version
	return r
}

// WithThreatType sets the threat type and returns the result for chaining.
func (r *ScanResult) WithThreatType(tt ThreatType) *ScanResult {
	r.ThreatType = tt
	return r
}

// WithSeverity sets the severity and returns the result for chaining.
func (r *ScanResult) WithSeverity(sev Severity) *ScanResult {
	r.Severity = sev
	return r
}

// SeverityFromDetection maps a ClamAV detection name to a severity level.
// ClamAV detection names follow patterns like: Win.Trojan.Agent-123, Linux.Ransomware.Cryptolocker
func SeverityFromDetection(detection string) Severity {
	if detection == "" {
		return SeverityUnknown
	}

	upper := strings.ToUpper(detection)

	// Critical: Trojans, Ransomware
	if strings.Contains(upper, "TROJAN") || strings.Contains(upper, "RANSOMWARE") {
		return SeverityCritical
	}

	// High: Viruses, Worms
	if strings.Contains(upper, "VIRUS") || strings.Contains(upper, "WORM") {
		return SeverityHigh
	}

	// Medium: Adware, PUA/PUP
	if strings.Contains(upper, "ADWARE") || strings.Contains(upper, "PUA") || strings.Contains(upper, "PUP") {
		return SeverityMedium
	}

	// Low: Heuristics, Test files
	if strings.Contains(upper, "HEURISTICS") || strings.Contains(upper, "EICAR") || strings.Contains(upper, "TEST") {
		return SeverityLow
	}

	// Default for unknown patterns
	return SeverityMedium
}

// ToSignature converts an infected ScanResult to a Signature for persistence.
// Returns nil if the result is not infected or missing required data.
func (r *ScanResult) ToSignature() *Signature {
	if r.Status != ScanStatusInfected {
		return nil
	}
	if r.FileHash == "" {
		return nil
	}
	if r.Detection == "" {
		return nil
	}

	return &Signature{
		SHA256:        r.FileHash,
		DetectionName: r.Detection,
		ThreatType:    r.ThreatType,
		Severity:      r.Severity,
		Source:        "clamav-scan",
		FirstSeen:     r.ScannedAt,
		Description:   "Detected by ClamAV scan",
	}
}

// ThreatTypeFromDetection maps a ClamAV detection name to a threat type.
func ThreatTypeFromDetection(detection string) ThreatType {
	if detection == "" {
		return ThreatTypeUnknown
	}

	upper := strings.ToUpper(detection)

	switch {
	case strings.Contains(upper, "TROJAN"):
		return ThreatTypeTrojan
	case strings.Contains(upper, "RANSOMWARE"):
		return ThreatTypeRansomware
	case strings.Contains(upper, "VIRUS"):
		return ThreatTypeVirus
	case strings.Contains(upper, "WORM"):
		return ThreatTypeWorm
	case strings.Contains(upper, "ADWARE"):
		return ThreatTypeAdware
	case strings.Contains(upper, "PUA"), strings.Contains(upper, "PUP"):
		return ThreatTypePUP
	case strings.Contains(upper, "SPYWARE"):
		return ThreatTypeSpyware
	case strings.Contains(upper, "EICAR"), strings.Contains(upper, "TEST"):
		return ThreatTypeTestFile
	default:
		return ThreatTypeMalware
	}
}
