// ABOUTME: Type definitions for Argus worker task messages and scan results
// ABOUTME: Aligned with AS3 integration spec for Redis-based communication

package argus

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// ScannerName represents a supported scanner type.
type ScannerName string

const (
	ScannerTrivy  ScannerName = "trivy"
	ScannerClamAV ScannerName = "clamav"
)

// ValidScanners is the list of supported scanners.
var ValidScanners = []ScannerName{ScannerTrivy, ScannerClamAV}

// IsValidScanner checks if a scanner name is supported.
func IsValidScanner(name string) bool {
	return slices.Contains(ValidScanners, ScannerName(name))
}

// ScannerStatus represents the status of a scanner.
type ScannerStatus string

const (
	StatusPending   ScannerStatus = "pending"
	StatusRunning   ScannerStatus = "running"
	StatusCompleted ScannerStatus = "completed"
	StatusFailed    ScannerStatus = "failed"
)

// IsValid checks if the status is a known value.
func (s ScannerStatus) IsValid() bool {
	switch s {
	case StatusPending, StatusRunning, StatusCompleted, StatusFailed:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if the status represents a final state.
func (s ScannerStatus) IsTerminal() bool {
	return s == StatusCompleted || s == StatusFailed
}

// TaskMessage is the message received from AS3 via Redis Streams.
type TaskMessage struct {
	// JobID is the unique identifier for this scan job.
	JobID string `json:"job_id"`

	// ReportID is the MongoDB ObjectId for the assessment report.
	ReportID string `json:"report_id"`

	// OrganizationID for IDOR protection and path validation.
	OrganizationID string `json:"organization_id"`

	// ParentTaskID is the AS3 task reference for tracing.
	ParentTaskID string `json:"parent_task_id"`

	// GCSURI is the GCS path to the skill archive.
	// Format: gs://bucket/org_id/skills/sha256.zip
	GCSURI string `json:"gcs_uri"`

	// Scanners is the list of scanners to run (e.g., ["trivy", "clamav"]).
	Scanners []string `json:"scanners"`

	// RetryCount tracks how many times this task has been retried.
	RetryCount int `json:"retry_count"`

	// TimeoutSeconds is the maximum time for this scan operation.
	TimeoutSeconds int `json:"timeout_seconds"`

	// TTLSeconds is the time-to-live for the task message.
	TTLSeconds int `json:"ttl_seconds"`

	// CreatedAt is when the task was created.
	CreatedAt time.Time `json:"created_at"`
}

// Validate checks that the task message has all required fields.
func (m *TaskMessage) Validate() error {
	if m.JobID == "" {
		return errors.New("job_id is required")
	}
	if m.OrganizationID == "" {
		return errors.New("organization_id is required")
	}
	if m.GCSURI == "" {
		return errors.New("gcs_uri is required")
	}
	if len(m.Scanners) == 0 {
		return errors.New("at least one scanner is required")
	}
	for _, s := range m.Scanners {
		if !IsValidScanner(s) {
			return fmt.Errorf("invalid scanner: %q (valid: trivy, clamav)", s)
		}
	}
	return nil
}

// HasScanner checks if the task includes a specific scanner.
func (m *TaskMessage) HasScanner(name ScannerName) bool {
	for _, s := range m.Scanners {
		if ScannerName(s) == name {
			return true
		}
	}
	return false
}

// Timeout returns the configured timeout as a duration.
func (m *TaskMessage) Timeout() time.Duration {
	if m.TimeoutSeconds > 0 {
		return time.Duration(m.TimeoutSeconds) * time.Second
	}
	return 15 * time.Minute // Default: 15 minutes.
}

// ArgusStatus tracks the status of each scanner.
type ArgusStatus struct {
	Trivy  ScannerStatus `json:"trivy"`
	ClamAV ScannerStatus `json:"clamav"`
}

// NewArgusStatus creates a new status with all scanners pending.
func NewArgusStatus() ArgusStatus {
	return ArgusStatus{
		Trivy:  StatusPending,
		ClamAV: StatusPending,
	}
}

// AllTerminal returns true if all scanners have reached a terminal state.
func (s ArgusStatus) AllTerminal() bool {
	return s.Trivy.IsTerminal() && s.ClamAV.IsTerminal()
}

// AnyFailed returns true if any scanner has failed.
func (s ArgusStatus) AnyFailed() bool {
	return s.Trivy == StatusFailed || s.ClamAV == StatusFailed
}

// TrivyResults holds Trivy scan findings.
type TrivyResults struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Secrets         []Secret        `json:"secrets,omitempty"`
	Dependencies    []Dependency    `json:"dependencies,omitempty"`
	Summary         TrivySummary    `json:"summary"`
	SecretSummary   *SecretSummary  `json:"secret_summary,omitempty"`
	ScanTimeMs      float64         `json:"scan_time_ms"`
}

// Vulnerability represents a CVE finding from Trivy.
type Vulnerability struct {
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	Ecosystem    string   `json:"ecosystem"`
	CVEID        string   `json:"cve_id"`
	Severity     string   `json:"severity"`
	Title        string   `json:"title,omitempty"`
	Description  string   `json:"description,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	References   []string `json:"references,omitempty"`
}

// Secret represents a detected secret from Trivy.
type Secret struct {
	RuleID    string `json:"rule_id"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Target    string `json:"target"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Match     string `json:"match,omitempty"`
}

// Dependency represents a package dependency.
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// TrivySummary provides vulnerability counts by severity.
type TrivySummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	PackagesScanned      int `json:"packages_scanned"`
}

// SecretSummary provides secret counts by severity.
type SecretSummary struct {
	TotalSecrets int `json:"total_secrets"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
}

// ClamAVResults holds ClamAV scan findings.
type ClamAVResults struct {
	InfectedFiles []InfectedFile  `json:"infected_files,omitempty"`
	ScanSummary   ClamScanSummary `json:"scan_summary"`
	ScanTimeMs    float64         `json:"scan_time_ms"`
}

// InfectedFile represents a file flagged by ClamAV.
type InfectedFile struct {
	Path       string `json:"path"`
	ThreatName string `json:"threat_name"`
	Hash       string `json:"hash,omitempty"`
}

// ClamScanSummary provides ClamAV scan statistics.
type ClamScanSummary struct {
	FilesScanned  int   `json:"files_scanned"`
	InfectedCount int   `json:"infected_count"`
	DataScanned   int64 `json:"data_scanned_bytes"`
}

// ArgusResults aggregates results from all scanners.
type ArgusResults struct {
	Trivy  *TrivyResults  `json:"trivy,omitempty"`
	ClamAV *ClamAVResults `json:"clamav,omitempty"`
	Errors map[string]string `json:"errors,omitempty"`
}

// HasErrors returns true if any scanner encountered an error.
func (r ArgusResults) HasErrors() bool {
	return len(r.Errors) > 0
}

// AddError records an error for a specific scanner.
func (r *ArgusResults) AddError(scanner, errMsg string) {
	if r.Errors == nil {
		r.Errors = make(map[string]string)
	}
	r.Errors[scanner] = errMsg
}

// CompletionSignal is published to Redis when scanning completes.
type CompletionSignal struct {
	JobID       string        `json:"job_id"`
	Status      string        `json:"status"` // "completed" or "failed"
	CompletedAt time.Time     `json:"completed_at"`
	Results     *ArgusResults `json:"results,omitempty"`
}
