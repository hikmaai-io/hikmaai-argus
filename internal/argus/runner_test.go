// ABOUTME: Unit tests for Argus scanner runner with mocked scanners
// ABOUTME: Tests parallel execution, error handling, and result aggregation

package argus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// MockTrivyScanner is a mock implementation for testing.
type MockTrivyScanner struct {
	Result *trivy.ScanResult
	Err    error
	Delay  time.Duration
}

func (m *MockTrivyScanner) ScanPath(ctx context.Context, path string, opts trivy.ScanOptions) (*trivy.ScanResult, error) {
	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.Result, m.Err
}

func (m *MockTrivyScanner) Ping(ctx context.Context) error {
	return nil
}

// MockClamAVScanner is a mock implementation for testing.
type MockClamAVScanner struct {
	Result *types.ScanResult
	Err    error
	Delay  time.Duration
}

func (m *MockClamAVScanner) ScanFile(ctx context.Context, path string) (*types.ScanResult, error) {
	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.Result, m.Err
}

func (m *MockClamAVScanner) ScanDirectory(ctx context.Context, path string) ([]*types.ScanResult, error) {
	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.Err != nil {
		return nil, m.Err
	}
	if m.Result != nil {
		return []*types.ScanResult{m.Result}, nil
	}
	return []*types.ScanResult{}, nil
}

func TestNewRunner(t *testing.T) {
	t.Parallel()

	cfg := RunnerConfig{
		TrivyScanner:  &MockTrivyScanner{},
		ClamAVScanner: &MockClamAVScanner{},
	}

	runner := NewRunner(cfg)
	if runner == nil {
		t.Error("NewRunner() returned nil")
	}
}

func TestRunner_RunTrivy(t *testing.T) {
	t.Parallel()

	trivyResult := &trivy.ScanResult{
		Summary: trivy.ScanSummary{
			TotalVulnerabilities: 2,
			Critical:             1,
			High:                 1,
			PackagesScanned:      5,
		},
		Vulnerabilities: []trivy.Vulnerability{
			{CVEID: "CVE-2023-1234", Severity: "CRITICAL", Package: "requests", Version: "2.25.0"},
			{CVEID: "CVE-2023-5678", Severity: "HIGH", Package: "flask", Version: "2.0.0"},
		},
		Secrets: []trivy.Secret{
			{RuleID: "aws-access-key", Severity: "CRITICAL", Title: "AWS Access Key"},
		},
		SecretSummary: trivy.NewSecretSummary([]trivy.Secret{
			{RuleID: "aws-access-key", Severity: "CRITICAL"},
		}),
		ScanTimeMs: 150.5,
	}

	runner := NewRunner(RunnerConfig{
		TrivyScanner: &MockTrivyScanner{Result: trivyResult},
	})

	ctx := context.Background()
	result, err := runner.RunTrivy(ctx, "/tmp/skill")
	if err != nil {
		t.Fatalf("RunTrivy() error = %v", err)
	}

	if result.Summary.TotalVulnerabilities != 2 {
		t.Errorf("TotalVulnerabilities = %d, want 2", result.Summary.TotalVulnerabilities)
	}
	if len(result.Vulnerabilities) != 2 {
		t.Errorf("Vulnerabilities len = %d, want 2", len(result.Vulnerabilities))
	}
	if len(result.Secrets) != 1 {
		t.Errorf("Secrets len = %d, want 1", len(result.Secrets))
	}
}

func TestRunner_RunTrivy_Error(t *testing.T) {
	t.Parallel()

	runner := NewRunner(RunnerConfig{
		TrivyScanner: &MockTrivyScanner{Err: errors.New("trivy failed")},
	})

	ctx := context.Background()
	_, err := runner.RunTrivy(ctx, "/tmp/skill")
	if err == nil {
		t.Error("RunTrivy() expected error, got nil")
	}
}

func TestRunner_RunClamAV(t *testing.T) {
	t.Parallel()

	clamResult := &types.ScanResult{
		Status:    types.ScanStatusInfected,
		Detection: "Trojan.Generic",
		FileHash:  "def456",
		FilePath:  "/tmp/malware.exe",
		FileSize:  1024,
	}

	runner := NewRunner(RunnerConfig{
		ClamAVScanner: &MockClamAVScanner{Result: clamResult},
	})

	ctx := context.Background()
	result, err := runner.RunClamAV(ctx, "/tmp/skill")
	if err != nil {
		t.Fatalf("RunClamAV() error = %v", err)
	}

	if result.ScanSummary.InfectedCount != 1 {
		t.Errorf("InfectedCount = %d, want 1", result.ScanSummary.InfectedCount)
	}
	if len(result.InfectedFiles) != 1 {
		t.Errorf("InfectedFiles len = %d, want 1", len(result.InfectedFiles))
	}
}

func TestRunner_RunClamAV_Clean(t *testing.T) {
	t.Parallel()

	clamResult := &types.ScanResult{
		Status:   types.ScanStatusClean,
		FileHash: "abc123",
		FilePath: "/tmp/clean.txt",
	}

	runner := NewRunner(RunnerConfig{
		ClamAVScanner: &MockClamAVScanner{Result: clamResult},
	})

	ctx := context.Background()
	result, err := runner.RunClamAV(ctx, "/tmp/skill")
	if err != nil {
		t.Fatalf("RunClamAV() error = %v", err)
	}

	if result.ScanSummary.InfectedCount != 0 {
		t.Errorf("InfectedCount = %d, want 0", result.ScanSummary.InfectedCount)
	}
}

func TestRunner_RunAll(t *testing.T) {
	t.Parallel()

	trivyResult := &trivy.ScanResult{
		Summary: trivy.ScanSummary{
			TotalVulnerabilities: 1,
			High:                 1,
			PackagesScanned:      3,
		},
		Vulnerabilities: []trivy.Vulnerability{
			{CVEID: "CVE-2023-1234", Severity: "HIGH"},
		},
		ScanTimeMs: 100,
	}

	clamResult := &types.ScanResult{
		Status:   types.ScanStatusClean,
		FileHash: "abc123",
	}

	runner := NewRunner(RunnerConfig{
		TrivyScanner:  &MockTrivyScanner{Result: trivyResult},
		ClamAVScanner: &MockClamAVScanner{Result: clamResult},
	})

	ctx := context.Background()
	results, err := runner.RunAll(ctx, "/tmp/skill", []string{"trivy", "clamav"})
	if err != nil {
		t.Fatalf("RunAll() error = %v", err)
	}

	if results.Trivy == nil {
		t.Error("Trivy results are nil")
	}
	if results.ClamAV == nil {
		t.Error("ClamAV results are nil")
	}
	if results.HasErrors() {
		t.Errorf("Unexpected errors: %v", results.Errors)
	}
}

func TestRunner_RunAll_PartialFailure(t *testing.T) {
	t.Parallel()

	trivyResult := &trivy.ScanResult{
		Summary: trivy.ScanSummary{PackagesScanned: 3},
	}

	runner := NewRunner(RunnerConfig{
		TrivyScanner:  &MockTrivyScanner{Result: trivyResult},
		ClamAVScanner: &MockClamAVScanner{Err: errors.New("clamav failed")},
	})

	ctx := context.Background()
	results, err := runner.RunAll(ctx, "/tmp/skill", []string{"trivy", "clamav"})

	// Should not return error; partial results are still useful.
	if err != nil {
		t.Fatalf("RunAll() error = %v (should return partial results)", err)
	}

	if results.Trivy == nil {
		t.Error("Trivy results should not be nil")
	}
	if results.ClamAV != nil {
		t.Error("ClamAV results should be nil on failure")
	}
	if !results.HasErrors() {
		t.Error("Expected errors map to contain clamav error")
	}
	if results.Errors["clamav"] == "" {
		t.Error("Expected clamav error message")
	}
}

func TestRunner_RunAll_Timeout(t *testing.T) {
	t.Parallel()

	runner := NewRunner(RunnerConfig{
		TrivyScanner:  &MockTrivyScanner{Delay: 5 * time.Second},
		ClamAVScanner: &MockClamAVScanner{Delay: 5 * time.Second},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	results, err := runner.RunAll(ctx, "/tmp/skill", []string{"trivy", "clamav"})

	// Both should have timeout errors.
	if err != nil {
		t.Fatalf("RunAll() error = %v", err)
	}

	if !results.HasErrors() {
		t.Error("Expected timeout errors")
	}
}

func TestRunner_RunAll_OnlyTrivy(t *testing.T) {
	t.Parallel()

	trivyResult := &trivy.ScanResult{
		Summary: trivy.ScanSummary{PackagesScanned: 5},
	}

	runner := NewRunner(RunnerConfig{
		TrivyScanner:  &MockTrivyScanner{Result: trivyResult},
		ClamAVScanner: &MockClamAVScanner{},
	})

	ctx := context.Background()
	results, err := runner.RunAll(ctx, "/tmp/skill", []string{"trivy"})
	if err != nil {
		t.Fatalf("RunAll() error = %v", err)
	}

	if results.Trivy == nil {
		t.Error("Trivy results should not be nil")
	}
	if results.ClamAV != nil {
		t.Error("ClamAV results should be nil when not requested")
	}
}

func TestRunner_ConvertTrivyResults(t *testing.T) {
	t.Parallel()

	trivyResult := &trivy.ScanResult{
		Summary: trivy.ScanSummary{
			TotalVulnerabilities: 2,
			Critical:             1,
			High:                 1,
			PackagesScanned:      10,
		},
		Vulnerabilities: []trivy.Vulnerability{
			{Package: "requests", Version: "2.25.0", CVEID: "CVE-2023-1234", Severity: "CRITICAL"},
			{Package: "flask", Version: "2.0.0", CVEID: "CVE-2023-5678", Severity: "HIGH"},
		},
		Secrets: []trivy.Secret{
			{RuleID: "aws-key", Category: "AWS", Severity: "CRITICAL", Title: "AWS Key"},
		},
		SecretSummary: trivy.NewSecretSummary([]trivy.Secret{
			{Severity: "CRITICAL"},
		}),
		ScanTimeMs: 200.5,
	}

	argusResult := ConvertTrivyResults(trivyResult)

	if argusResult.Summary.TotalVulnerabilities != 2 {
		t.Errorf("TotalVulnerabilities = %d, want 2", argusResult.Summary.TotalVulnerabilities)
	}
	if len(argusResult.Vulnerabilities) != 2 {
		t.Errorf("Vulnerabilities len = %d, want 2", len(argusResult.Vulnerabilities))
	}
	if len(argusResult.Secrets) != 1 {
		t.Errorf("Secrets len = %d, want 1", len(argusResult.Secrets))
	}
	if argusResult.ScanTimeMs != 200.5 {
		t.Errorf("ScanTimeMs = %f, want 200.5", argusResult.ScanTimeMs)
	}
}
