// ABOUTME: Tests for ScanResult type used in ClamAV file scanning
// ABOUTME: Validates status transitions, constructors, and severity mapping

package types

import (
	"testing"
	"time"
)

func TestScanStatus_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status ScanStatus
		want   string
	}{
		{name: "clean", status: ScanStatusClean, want: "clean"},
		{name: "infected", status: ScanStatusInfected, want: "infected"},
		{name: "error", status: ScanStatusError, want: "error"},
		{name: "unknown default", status: ScanStatus(99), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.String(); got != tt.want {
				t.Errorf("ScanStatus.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScanStatus_IsInfected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status ScanStatus
		want   bool
	}{
		{name: "clean is not infected", status: ScanStatusClean, want: false},
		{name: "infected is infected", status: ScanStatusInfected, want: true},
		{name: "error is not infected", status: ScanStatusError, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsInfected(); got != tt.want {
				t.Errorf("ScanStatus.IsInfected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewCleanScanResult(t *testing.T) {
	t.Parallel()

	result := NewCleanScanResult("/path/to/file.txt", "abc123", 1024)

	if result.FilePath != "/path/to/file.txt" {
		t.Errorf("FilePath = %q, want %q", result.FilePath, "/path/to/file.txt")
	}
	if result.FileHash != "abc123" {
		t.Errorf("FileHash = %q, want %q", result.FileHash, "abc123")
	}
	if result.FileSize != 1024 {
		t.Errorf("FileSize = %d, want %d", result.FileSize, 1024)
	}
	if result.Status != ScanStatusClean {
		t.Errorf("Status = %v, want %v", result.Status, ScanStatusClean)
	}
	if result.Detection != "" {
		t.Errorf("Detection should be empty for clean result, got %q", result.Detection)
	}
	if result.Engine != "clamav" {
		t.Errorf("Engine = %q, want %q", result.Engine, "clamav")
	}
	if result.ScannedAt.IsZero() {
		t.Error("ScannedAt should not be zero")
	}
}

func TestNewInfectedScanResult(t *testing.T) {
	t.Parallel()

	result := NewInfectedScanResult("/path/to/malware.exe", "def456", 2048, "Win.Trojan.Agent-123")

	if result.FilePath != "/path/to/malware.exe" {
		t.Errorf("FilePath = %q, want %q", result.FilePath, "/path/to/malware.exe")
	}
	if result.FileHash != "def456" {
		t.Errorf("FileHash = %q, want %q", result.FileHash, "def456")
	}
	if result.FileSize != 2048 {
		t.Errorf("FileSize = %d, want %d", result.FileSize, 2048)
	}
	if result.Status != ScanStatusInfected {
		t.Errorf("Status = %v, want %v", result.Status, ScanStatusInfected)
	}
	if result.Detection != "Win.Trojan.Agent-123" {
		t.Errorf("Detection = %q, want %q", result.Detection, "Win.Trojan.Agent-123")
	}
	if result.Engine != "clamav" {
		t.Errorf("Engine = %q, want %q", result.Engine, "clamav")
	}
}

func TestNewErrorScanResult(t *testing.T) {
	t.Parallel()

	result := NewErrorScanResult("/path/to/file.txt", "connection refused")

	if result.FilePath != "/path/to/file.txt" {
		t.Errorf("FilePath = %q, want %q", result.FilePath, "/path/to/file.txt")
	}
	if result.Status != ScanStatusError {
		t.Errorf("Status = %v, want %v", result.Status, ScanStatusError)
	}
	if result.Error != "connection refused" {
		t.Errorf("Error = %q, want %q", result.Error, "connection refused")
	}
}

func TestScanResult_WithScanTime(t *testing.T) {
	t.Parallel()

	result := NewCleanScanResult("/path/to/file.txt", "abc123", 1024).
		WithScanTime(150.5)

	if result.ScanTimeMs != 150.5 {
		t.Errorf("ScanTimeMs = %f, want %f", result.ScanTimeMs, 150.5)
	}
}

func TestScanResult_WithEngineVersion(t *testing.T) {
	t.Parallel()

	result := NewCleanScanResult("/path/to/file.txt", "abc123", 1024).
		WithEngineVersion("0.104.2")

	if result.EngineVersion != "0.104.2" {
		t.Errorf("EngineVersion = %q, want %q", result.EngineVersion, "0.104.2")
	}
}

func TestScanResult_Chaining(t *testing.T) {
	t.Parallel()

	result := NewInfectedScanResult("/path/to/malware.exe", "hash123", 4096, "Eicar-Test-Signature").
		WithScanTime(25.3).
		WithEngineVersion("0.104.2").
		WithThreatType(ThreatTypeTestFile).
		WithSeverity(SeverityLow)

	if result.ScanTimeMs != 25.3 {
		t.Errorf("ScanTimeMs = %f, want %f", result.ScanTimeMs, 25.3)
	}
	if result.EngineVersion != "0.104.2" {
		t.Errorf("EngineVersion = %q, want %q", result.EngineVersion, "0.104.2")
	}
	if result.ThreatType != ThreatTypeTestFile {
		t.Errorf("ThreatType = %v, want %v", result.ThreatType, ThreatTypeTestFile)
	}
	if result.Severity != SeverityLow {
		t.Errorf("Severity = %v, want %v", result.Severity, SeverityLow)
	}
}

func TestScanResult_IsInfected(t *testing.T) {
	t.Parallel()

	cleanResult := NewCleanScanResult("/path/to/file.txt", "abc123", 1024)
	if cleanResult.IsInfected() {
		t.Error("Clean result should not be infected")
	}

	infectedResult := NewInfectedScanResult("/path/to/malware.exe", "def456", 2048, "Win.Trojan.Agent")
	if !infectedResult.IsInfected() {
		t.Error("Infected result should be infected")
	}
}

func TestSeverityFromDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		detection string
		want      Severity
	}{
		{name: "trojan is critical", detection: "Win.Trojan.Agent-123", want: SeverityCritical},
		{name: "ransomware is critical", detection: "Linux.Ransomware.Cryptolocker", want: SeverityCritical},
		{name: "virus is high", detection: "Win.Virus.Sality", want: SeverityHigh},
		{name: "worm is high", detection: "Email.Worm.Mydoom", want: SeverityHigh},
		{name: "adware is medium", detection: "Win.Adware.Toolbar", want: SeverityMedium},
		{name: "pua is medium", detection: "Win.PUA.Optimizer", want: SeverityMedium},
		{name: "heuristics is low", detection: "Heuristics.Encrypted.PDF", want: SeverityLow},
		{name: "unknown pattern is medium", detection: "Something.Else.Unknown", want: SeverityMedium},
		{name: "empty detection is unknown", detection: "", want: SeverityUnknown},
		{name: "eicar test is low", detection: "Eicar-Test-Signature", want: SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SeverityFromDetection(tt.detection); got != tt.want {
				t.Errorf("SeverityFromDetection(%q) = %v, want %v", tt.detection, got, tt.want)
			}
		})
	}
}

func TestThreatTypeFromDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		detection string
		want      ThreatType
	}{
		{name: "trojan", detection: "Win.Trojan.Agent-123", want: ThreatTypeTrojan},
		{name: "ransomware", detection: "Linux.Ransomware.Cryptolocker", want: ThreatTypeRansomware},
		{name: "virus", detection: "Win.Virus.Sality", want: ThreatTypeVirus},
		{name: "worm", detection: "Email.Worm.Mydoom", want: ThreatTypeWorm},
		{name: "adware", detection: "Win.Adware.Toolbar", want: ThreatTypeAdware},
		{name: "pua", detection: "Win.PUA.Optimizer", want: ThreatTypePUP},
		{name: "spyware", detection: "Win.Spyware.Keylogger", want: ThreatTypeSpyware},
		{name: "eicar test", detection: "Eicar-Test-Signature", want: ThreatTypeTestFile},
		{name: "unknown pattern", detection: "Something.Else.Unknown", want: ThreatTypeMalware},
		{name: "empty detection", detection: "", want: ThreatTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ThreatTypeFromDetection(tt.detection); got != tt.want {
				t.Errorf("ThreatTypeFromDetection(%q) = %v, want %v", tt.detection, got, tt.want)
			}
		})
	}
}

func TestScanResult_ToSignature(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		result   *ScanResult
		wantNil  bool
		wantSHA  string
		wantName string
	}{
		{
			name:     "infected result converts to signature",
			result:   NewInfectedScanResult("/path/to/malware.exe", "abc123hash", 2048, "Win.Trojan.Agent"),
			wantNil:  false,
			wantSHA:  "abc123hash",
			wantName: "Win.Trojan.Agent",
		},
		{
			name:    "clean result returns nil",
			result:  NewCleanScanResult("/path/to/file.txt", "def456hash", 1024),
			wantNil: true,
		},
		{
			name:    "error result returns nil",
			result:  NewErrorScanResult("/path/to/file.txt", "some error"),
			wantNil: true,
		},
		{
			name: "infected result without hash returns nil",
			result: &ScanResult{
				Status:    ScanStatusInfected,
				Detection: "Win.Trojan.Agent",
			},
			wantNil: true,
		},
		{
			name: "infected result without detection returns nil",
			result: &ScanResult{
				Status:   ScanStatusInfected,
				FileHash: "abc123hash",
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sig := tt.result.ToSignature()

			if tt.wantNil {
				if sig != nil {
					t.Errorf("ToSignature() = %v, want nil", sig)
				}
				return
			}

			if sig == nil {
				t.Fatal("ToSignature() = nil, want signature")
			}
			if sig.SHA256 != tt.wantSHA {
				t.Errorf("SHA256 = %q, want %q", sig.SHA256, tt.wantSHA)
			}
			if sig.DetectionName != tt.wantName {
				t.Errorf("DetectionName = %q, want %q", sig.DetectionName, tt.wantName)
			}
			if sig.Source != "clamav-scan" {
				t.Errorf("Source = %q, want %q", sig.Source, "clamav-scan")
			}
		})
	}
}

func TestScanResult_WithFileInfo(t *testing.T) {
	t.Parallel()

	result := NewErrorScanResult("/path/to/file.txt", "clamscan error: no database").
		WithFileInfo(2048, "abc123hash")

	if result.FileSize != 2048 {
		t.Errorf("FileSize = %d, want %d", result.FileSize, 2048)
	}
	if result.FileHash != "abc123hash" {
		t.Errorf("FileHash = %q, want %q", result.FileHash, "abc123hash")
	}
	// Verify error status and message are preserved.
	if result.Status != ScanStatusError {
		t.Errorf("Status = %v, want %v", result.Status, ScanStatusError)
	}
	if result.Error != "clamscan error: no database" {
		t.Errorf("Error = %q, want %q", result.Error, "clamscan error: no database")
	}
}

func TestScanResult_ScannedAtIsUTC(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC()
	result := NewCleanScanResult("/path/to/file.txt", "abc123", 1024)
	after := time.Now().UTC()

	if result.ScannedAt.Location() != time.UTC {
		t.Error("ScannedAt should be in UTC")
	}
	if result.ScannedAt.Before(before) || result.ScannedAt.After(after) {
		t.Errorf("ScannedAt = %v, should be between %v and %v", result.ScannedAt, before, after)
	}
}
