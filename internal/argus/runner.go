// ABOUTME: Scanner runner that orchestrates Trivy and ClamAV scans
// ABOUTME: Supports parallel execution, error aggregation, and result conversion

package argus

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// TrivyScanner defines the interface for Trivy scanning.
type TrivyScanner interface {
	ScanPath(ctx context.Context, path string, opts trivy.ScanOptions) (*trivy.ScanResult, error)
	Ping(ctx context.Context) error
}

// ClamAVScanner defines the interface for ClamAV scanning.
type ClamAVScanner interface {
	ScanFile(ctx context.Context, path string) (*types.ScanResult, error)
	ScanDirectory(ctx context.Context, path string) ([]*types.ScanResult, error)
}

// RunnerConfig holds configuration for the scanner runner.
type RunnerConfig struct {
	TrivyScanner  TrivyScanner
	ClamAVScanner ClamAVScanner
}

// Runner orchestrates vulnerability and malware scanning.
type Runner struct {
	trivyScanner  TrivyScanner
	clamavScanner ClamAVScanner
}

// NewRunner creates a new scanner runner.
func NewRunner(cfg RunnerConfig) *Runner {
	return &Runner{
		trivyScanner:  cfg.TrivyScanner,
		clamavScanner: cfg.ClamAVScanner,
	}
}

// RunTrivy runs the Trivy scanner on the given path.
func (r *Runner) RunTrivy(ctx context.Context, path string) (*TrivyResults, error) {
	if r.trivyScanner == nil {
		return nil, fmt.Errorf("trivy scanner not configured")
	}

	opts := trivy.ScanOptions{
		SeverityFilter: []string{trivy.SeverityCritical, trivy.SeverityHigh},
		ScanSecrets:    true,
	}

	result, err := r.trivyScanner.ScanPath(ctx, path, opts)
	if err != nil {
		return nil, fmt.Errorf("trivy scan: %w", err)
	}

	return ConvertTrivyResults(result), nil
}

// RunClamAV runs the ClamAV scanner on the given directory.
func (r *Runner) RunClamAV(ctx context.Context, path string) (*ClamAVResults, error) {
	if r.clamavScanner == nil {
		return nil, fmt.Errorf("clamav scanner not configured")
	}

	start := time.Now()

	// Scan the directory.
	results, err := r.clamavScanner.ScanDirectory(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("clamav scan: %w", err)
	}

	return ConvertClamAVResults(results, time.Since(start)), nil
}

// RunAll runs all requested scanners in parallel and aggregates results.
// Returns partial results on individual scanner failures (fail-open).
func (r *Runner) RunAll(ctx context.Context, path string, scanners []string) (*ArgusResults, error) {
	results := &ArgusResults{
		Errors: make(map[string]string),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Determine which scanners to run.
	runTrivy := false
	runClamAV := false
	for _, s := range scanners {
		switch ScannerName(s) {
		case ScannerTrivy:
			runTrivy = true
		case ScannerClamAV:
			runClamAV = true
		}
	}

	// Run Trivy.
	if runTrivy && r.trivyScanner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			trivyResult, err := r.RunTrivy(ctx, path)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				results.Errors["trivy"] = err.Error()
			} else {
				results.Trivy = trivyResult
			}
		}()
	}

	// Run ClamAV.
	if runClamAV && r.clamavScanner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			clamResult, err := r.RunClamAV(ctx, path)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				results.Errors["clamav"] = err.Error()
			} else {
				results.ClamAV = clamResult
			}
		}()
	}

	wg.Wait()

	// Clear errors map if empty (for cleaner JSON output).
	if len(results.Errors) == 0 {
		results.Errors = nil
	}

	return results, nil
}

// ConvertTrivyResults converts Trivy scan results to Argus types.
func ConvertTrivyResults(tr *trivy.ScanResult) *TrivyResults {
	if tr == nil {
		return nil
	}

	result := &TrivyResults{
		Summary: TrivySummary{
			TotalVulnerabilities: tr.Summary.TotalVulnerabilities,
			Critical:             tr.Summary.Critical,
			High:                 tr.Summary.High,
			Medium:               tr.Summary.Medium,
			Low:                  tr.Summary.Low,
			PackagesScanned:      tr.Summary.PackagesScanned,
		},
		ScanTimeMs: tr.ScanTimeMs,
	}

	// Convert vulnerabilities.
	for _, v := range tr.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Package:      v.Package,
			Version:      v.Version,
			Ecosystem:    v.Ecosystem,
			CVEID:        v.CVEID,
			Severity:     v.Severity,
			Title:        v.Title,
			Description:  v.Description,
			FixedVersion: v.FixedVersion,
			References:   v.References,
		})
	}

	// Convert secrets.
	for _, s := range tr.Secrets {
		result.Secrets = append(result.Secrets, Secret{
			RuleID:    s.RuleID,
			Category:  s.Category,
			Severity:  s.Severity,
			Title:     s.Title,
			Target:    s.Target,
			StartLine: s.StartLine,
			EndLine:   s.EndLine,
			Match:     s.Match,
		})
	}

	// Convert secret summary.
	if tr.SecretSummary != nil {
		result.SecretSummary = &SecretSummary{
			TotalSecrets: tr.SecretSummary.TotalSecrets,
			Critical:     tr.SecretSummary.Critical,
			High:         tr.SecretSummary.High,
			Medium:       tr.SecretSummary.Medium,
			Low:          tr.SecretSummary.Low,
		}
	}

	return result
}

// ConvertClamAVResults converts ClamAV scan results to Argus types.
func ConvertClamAVResults(results []*types.ScanResult, elapsed time.Duration) *ClamAVResults {
	clamResults := &ClamAVResults{
		ScanSummary: ClamScanSummary{
			FilesScanned: len(results),
		},
		ScanTimeMs: float64(elapsed.Milliseconds()),
	}

	var totalSize int64
	for _, r := range results {
		totalSize += r.FileSize

		if r.Status == types.ScanStatusInfected {
			clamResults.InfectedFiles = append(clamResults.InfectedFiles, InfectedFile{
				Path:       filepath.Base(r.FilePath),
				ThreatName: r.Detection,
				Hash:       r.FileHash,
			})
			clamResults.ScanSummary.InfectedCount++
		}
	}

	clamResults.ScanSummary.DataScanned = totalSize

	return clamResults
}
