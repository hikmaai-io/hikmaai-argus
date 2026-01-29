// ABOUTME: Tests for Signature type representing malware signatures
// ABOUTME: Covers signature creation, validation, and JSON serialization

package types_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hikmaai-io/hikma-av/internal/types"
)

func TestNewSignature(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		sha256        string
		detectionName string
		source        string
		wantErr       bool
	}{
		{
			name:          "valid signature",
			sha256:        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
			detectionName: "EICAR-Test-File",
			source:        "clamav",
		},
		{
			name:          "empty sha256",
			sha256:        "",
			detectionName: "Test",
			source:        "test",
			wantErr:       true,
		},
		{
			name:          "empty detection name",
			sha256:        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
			detectionName: "",
			source:        "test",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sig, err := types.NewSignature(tt.sha256, tt.detectionName, tt.source)

			if tt.wantErr {
				if err == nil {
					t.Error("NewSignature() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewSignature() unexpected error: %v", err)
				return
			}

			if sig.SHA256 != tt.sha256 {
				t.Errorf("Signature.SHA256 = %v, want %v", sig.SHA256, tt.sha256)
			}
			if sig.DetectionName != tt.detectionName {
				t.Errorf("Signature.DetectionName = %v, want %v", sig.DetectionName, tt.detectionName)
			}
			if sig.Source != tt.source {
				t.Errorf("Signature.Source = %v, want %v", sig.Source, tt.source)
			}
			if sig.FirstSeen.IsZero() {
				t.Error("Signature.FirstSeen should not be zero")
			}
		})
	}
}

func TestSignature_WithHashes(t *testing.T) {
	t.Parallel()

	sig, err := types.NewSignature(
		"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		"EICAR-Test-File",
		"clamav",
	)
	if err != nil {
		t.Fatalf("NewSignature() error: %v", err)
	}

	sha1 := "3395856ce81f2b7382dee72602f798b642f14140"
	md5 := "44d88612fea8a8f36de82e1278abb02f"

	sig = sig.WithSHA1(sha1).WithMD5(md5)

	if sig.SHA1 != sha1 {
		t.Errorf("Signature.SHA1 = %v, want %v", sig.SHA1, sha1)
	}
	if sig.MD5 != md5 {
		t.Errorf("Signature.MD5 = %v, want %v", sig.MD5, md5)
	}
}

func TestSignature_WithThreatInfo(t *testing.T) {
	t.Parallel()

	sig, err := types.NewSignature(
		"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		"EICAR-Test-File",
		"clamav",
	)
	if err != nil {
		t.Fatalf("NewSignature() error: %v", err)
	}

	sig = sig.WithThreatType(types.ThreatTypeTrojan).WithSeverity(types.SeverityHigh)

	if sig.ThreatType != types.ThreatTypeTrojan {
		t.Errorf("Signature.ThreatType = %v, want %v", sig.ThreatType, types.ThreatTypeTrojan)
	}
	if sig.Severity != types.SeverityHigh {
		t.Errorf("Signature.Severity = %v, want %v", sig.Severity, types.SeverityHigh)
	}
}

func TestSignature_JSON(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	sig := types.Signature{
		SHA256:        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		SHA1:          "3395856ce81f2b7382dee72602f798b642f14140",
		MD5:           "44d88612fea8a8f36de82e1278abb02f",
		DetectionName: "EICAR-Test-File",
		ThreatType:    types.ThreatTypeTestFile,
		Severity:      types.SeverityLow,
		Source:        "eicar",
		FirstSeen:     now,
	}

	// Marshal to JSON.
	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	// Unmarshal back.
	var decoded types.Signature
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	// Compare fields.
	if decoded.SHA256 != sig.SHA256 {
		t.Errorf("SHA256 = %v, want %v", decoded.SHA256, sig.SHA256)
	}
	if decoded.SHA1 != sig.SHA1 {
		t.Errorf("SHA1 = %v, want %v", decoded.SHA1, sig.SHA1)
	}
	if decoded.MD5 != sig.MD5 {
		t.Errorf("MD5 = %v, want %v", decoded.MD5, sig.MD5)
	}
	if decoded.DetectionName != sig.DetectionName {
		t.Errorf("DetectionName = %v, want %v", decoded.DetectionName, sig.DetectionName)
	}
	if decoded.ThreatType != sig.ThreatType {
		t.Errorf("ThreatType = %v, want %v", decoded.ThreatType, sig.ThreatType)
	}
	if decoded.Severity != sig.Severity {
		t.Errorf("Severity = %v, want %v", decoded.Severity, sig.Severity)
	}
	if decoded.Source != sig.Source {
		t.Errorf("Source = %v, want %v", decoded.Source, sig.Source)
	}
}

func TestThreatType_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		threatType types.ThreatType
		want       string
	}{
		{name: "Unknown", threatType: types.ThreatTypeUnknown, want: "unknown"},
		{name: "Trojan", threatType: types.ThreatTypeTrojan, want: "trojan"},
		{name: "Virus", threatType: types.ThreatTypeVirus, want: "virus"},
		{name: "Worm", threatType: types.ThreatTypeWorm, want: "worm"},
		{name: "Ransomware", threatType: types.ThreatTypeRansomware, want: "ransomware"},
		{name: "Adware", threatType: types.ThreatTypeAdware, want: "adware"},
		{name: "Spyware", threatType: types.ThreatTypeSpyware, want: "spyware"},
		{name: "PUP", threatType: types.ThreatTypePUP, want: "pup"},
		{name: "TestFile", threatType: types.ThreatTypeTestFile, want: "testfile"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.threatType.String(); got != tt.want {
				t.Errorf("ThreatType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverity_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity types.Severity
		want     string
	}{
		{name: "Unknown", severity: types.SeverityUnknown, want: "unknown"},
		{name: "Low", severity: types.SeverityLow, want: "low"},
		{name: "Medium", severity: types.SeverityMedium, want: "medium"},
		{name: "High", severity: types.SeverityHigh, want: "high"},
		{name: "Critical", severity: types.SeverityCritical, want: "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.severity.String(); got != tt.want {
				t.Errorf("Severity.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
