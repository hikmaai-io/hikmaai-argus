// ABOUTME: Tests for Result type representing scan results
// ABOUTME: Covers result status, creation, and JSON serialization

package types_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestStatus_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status types.Status
		want   string
	}{
		{name: "Unknown", status: types.StatusUnknown, want: "unknown"},
		{name: "Clean", status: types.StatusClean, want: "clean"},
		{name: "Malware", status: types.StatusMalware, want: "malware"},
		{name: "Error", status: types.StatusError, want: "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.String(); got != tt.want {
				t.Errorf("Status.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatus_IsMalicious(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status types.Status
		want   bool
	}{
		{name: "Unknown is not malicious", status: types.StatusUnknown, want: false},
		{name: "Clean is not malicious", status: types.StatusClean, want: false},
		{name: "Malware is malicious", status: types.StatusMalware, want: true},
		{name: "Error is not malicious", status: types.StatusError, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsMalicious(); got != tt.want {
				t.Errorf("Status.IsMalicious() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewCleanResult(t *testing.T) {
	t.Parallel()

	hash := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	}

	result := types.NewCleanResult(hash)

	if result.Status != types.StatusClean {
		t.Errorf("Result.Status = %v, want %v", result.Status, types.StatusClean)
	}
	if result.Hash != hash {
		t.Errorf("Result.Hash = %v, want %v", result.Hash, hash)
	}
	if result.Signature != nil {
		t.Error("Result.Signature should be nil for clean result")
	}
	if result.ScannedAt.IsZero() {
		t.Error("Result.ScannedAt should not be zero")
	}
}

func TestNewMalwareResult(t *testing.T) {
	t.Parallel()

	hash := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	}
	sig := &types.Signature{
		SHA256:        hash.Value,
		DetectionName: "EICAR-Test-File",
		ThreatType:    types.ThreatTypeTestFile,
		Severity:      types.SeverityLow,
		Source:        "eicar",
	}

	result := types.NewMalwareResult(hash, sig)

	if result.Status != types.StatusMalware {
		t.Errorf("Result.Status = %v, want %v", result.Status, types.StatusMalware)
	}
	if result.Hash != hash {
		t.Errorf("Result.Hash = %v, want %v", result.Hash, hash)
	}
	if result.Signature == nil {
		t.Fatal("Result.Signature should not be nil for malware result")
	}
	if result.Signature.DetectionName != sig.DetectionName {
		t.Errorf("Result.Signature.DetectionName = %v, want %v", result.Signature.DetectionName, sig.DetectionName)
	}
}

func TestNewUnknownResult(t *testing.T) {
	t.Parallel()

	hash := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	}

	result := types.NewUnknownResult(hash)

	if result.Status != types.StatusUnknown {
		t.Errorf("Result.Status = %v, want %v", result.Status, types.StatusUnknown)
	}
}

func TestNewErrorResult(t *testing.T) {
	t.Parallel()

	hash := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	}
	errMsg := "database connection failed"

	result := types.NewErrorResult(hash, errMsg)

	if result.Status != types.StatusError {
		t.Errorf("Result.Status = %v, want %v", result.Status, types.StatusError)
	}
	if result.Error != errMsg {
		t.Errorf("Result.Error = %v, want %v", result.Error, errMsg)
	}
}

func TestResult_JSON(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	hash := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	}
	sig := &types.Signature{
		SHA256:        hash.Value,
		DetectionName: "EICAR-Test-File",
		ThreatType:    types.ThreatTypeTestFile,
		Severity:      types.SeverityLow,
		Source:        "eicar",
		FirstSeen:     now,
	}
	result := types.Result{
		Hash:      hash,
		Status:    types.StatusMalware,
		Signature: sig,
		ScannedAt: now,
	}

	// Marshal to JSON.
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	// Unmarshal back.
	var decoded types.Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	// Compare fields.
	if decoded.Status != result.Status {
		t.Errorf("Status = %v, want %v", decoded.Status, result.Status)
	}
	if decoded.Hash.Value != result.Hash.Value {
		t.Errorf("Hash.Value = %v, want %v", decoded.Hash.Value, result.Hash.Value)
	}
	if decoded.Signature == nil {
		t.Fatal("Signature should not be nil")
	}
	if decoded.Signature.DetectionName != sig.DetectionName {
		t.Errorf("Signature.DetectionName = %v, want %v", decoded.Signature.DetectionName, sig.DetectionName)
	}
}

func TestResult_IsMalicious(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result types.Result
		want   bool
	}{
		{
			name:   "clean is not malicious",
			result: types.Result{Status: types.StatusClean},
			want:   false,
		},
		{
			name:   "malware is malicious",
			result: types.Result{Status: types.StatusMalware},
			want:   true,
		},
		{
			name:   "unknown is not malicious",
			result: types.Result{Status: types.StatusUnknown},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.result.IsMalicious(); got != tt.want {
				t.Errorf("Result.IsMalicious() = %v, want %v", got, tt.want)
			}
		})
	}
}
