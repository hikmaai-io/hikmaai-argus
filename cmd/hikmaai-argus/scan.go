// ABOUTME: Scan command for checking hashes against the signature database
// ABOUTME: Supports single hash, file input, batch modes, ClamAV file scanning, and Trivy dependency scanning

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikmaai-argus/internal/config"
	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/scanner"
	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func newScanCmd() *cobra.Command {
	var (
		fileInput      string
		batch          string
		direct         bool
		nats           bool
		outputJSON     bool
		dataDir        string
		clamDBDir      string
		withFile       string
		recursive      bool
		clamdAddress   string
		persistMalware bool
		withDeps       bool
		trivyServer    string
	)

	cmd := &cobra.Command{
		Use:   "scan [hash]",
		Short: "Scan a hash or file for malware",
		Long: `Scan hashes against the signature database or files with ClamAV.

HASH LOOKUP MODE (default):
  Checks hashes against the signature database for known malware.

FILE SCAN MODE (--with-file):
  Scans files with ClamAV for malware detection.
  Requires clamscan to be installed and ClamAV databases available.

Examples:
  # Hash lookup
  hikmaai-argus scan 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  hikmaai-argus scan --file hashes.txt
  hikmaai-argus scan --batch "hash1,hash2,hash3"

  # File scanning with ClamAV
  hikmaai-argus scan --with-file /path/to/suspicious.exe
  hikmaai-argus scan --with-file /path/to/directory --recursive
  hikmaai-argus scan --with-file /path/to/file.exe --persist  # Save detections to DB

  # Combined scan (ClamAV malware + Trivy dependencies)
  hikmaai-argus scan --with-file /path/to/app.zip --with-deps
  hikmaai-argus scan --with-file /path/to/project --with-deps --recursive
  hikmaai-argus scan --with-file /path/to/project --with-deps --trivy-server http://trivy:4954  # Use server mode`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// File scan mode.
			if withFile != "" {
				cfg := &config.ClamAVConfig{
					Mode:        "clamscan",
					Binary:      "clamscan",
					DatabaseDir: clamDBDir,
					Address:     clamdAddress,
					Timeout:     5 * time.Minute,
				}

				return scanWithClamAV(ctx, withFile, recursive, cfg, dataDir, outputJSON, persistMalware, withDeps, trivyServer)
			}

			// Hash lookup mode.
			var hashes []string

			if len(args) > 0 {
				hashes = append(hashes, args[0])
			}

			if fileInput != "" {
				fileHashes, err := readHashesFromFile(fileInput)
				if err != nil {
					return fmt.Errorf("reading hashes from file: %w", err)
				}
				hashes = append(hashes, fileHashes...)
			}

			if batch != "" {
				batchHashes := strings.Split(batch, ",")
				for _, h := range batchHashes {
					h = strings.TrimSpace(h)
					if h != "" {
						hashes = append(hashes, h)
					}
				}
			}

			if len(hashes) == 0 {
				return fmt.Errorf("no hashes provided; use positional argument, --file, --batch, or --with-file")
			}

			if nats && direct {
				return fmt.Errorf("cannot use both --nats and --direct")
			}

			return scanDirect(ctx, hashes, dataDir, outputJSON)
		},
	}

	// Hash lookup flags.
	cmd.Flags().StringVarP(&fileInput, "file", "f", "", "file containing hashes (one per line)")
	cmd.Flags().StringVarP(&batch, "batch", "b", "", "comma-separated list of hashes")
	cmd.Flags().BoolVar(&direct, "direct", false, "force direct database access (skip NATS check)")
	cmd.Flags().BoolVar(&nats, "nats", false, "force NATS (fail if no daemon)")
	cmd.Flags().BoolVarP(&outputJSON, "json", "j", false, "output results as JSON")
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for HikmaAI signatures")
	cmd.Flags().StringVar(&clamDBDir, "clamdb-dir", config.DefaultClamDBDir(), "directory for ClamAV databases (CVD files)")

	// ClamAV file scanning flags.
	cmd.Flags().StringVar(&withFile, "with-file", "", "path to file or directory to scan with ClamAV")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "scan directories recursively")
	cmd.Flags().StringVar(&clamdAddress, "clamd-address", "", "clamd address (for clamd mode)")
	cmd.Flags().BoolVar(&persistMalware, "persist", false, "persist malware detections to signature database")

	// Trivy dependency scanning flags (used with --with-file).
	cmd.Flags().BoolVar(&withDeps, "with-deps", false, "also scan for dependency vulnerabilities and secrets")
	cmd.Flags().StringVar(&trivyServer, "trivy-server", "", "Trivy server URL (uses local trivy if not set)")

	return cmd
}

func scanDirect(ctx context.Context, hashes []string, dataDir string, outputJSON bool) error {
	// Create engine with bloom filter rebuilt from existing signatures.
	eng, err := engine.NewEngine(engine.EngineConfig{
		StoreConfig: engine.StoreConfig{
			Path: dataDir,
		},
		BloomConfig: engine.BloomConfig{
			ExpectedItems:     10_000_000,
			FalsePositiveRate: 0.001,
		},
		RebuildBloomOnStart: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}
	defer eng.Close()

	// Scan each hash.
	results := make([]types.Result, 0, len(hashes))
	for _, hashStr := range hashes {
		hash, err := types.ParseHash(hashStr)
		if err != nil {
			if outputJSON {
				results = append(results, types.NewErrorResult(types.Hash{Value: hashStr}, err.Error()))
			} else {
				fmt.Fprintf(os.Stderr, "invalid hash %q: %v\n", hashStr, err)
			}
			continue
		}

		result, err := eng.Lookup(ctx, hash)
		if err != nil {
			if outputJSON {
				results = append(results, types.NewErrorResult(hash, err.Error()))
			} else {
				fmt.Fprintf(os.Stderr, "lookup error for %s: %v\n", hashStr, err)
			}
			continue
		}

		results = append(results, result)

		if !outputJSON {
			printResult(result)
		}
	}

	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	return nil
}

func printResult(result types.Result) {
	fmt.Printf("Hash:   %s (%s)\n", result.Hash.Value, result.Hash.Type)
	fmt.Printf("Status: %s\n", result.Status)

	if result.Status == types.StatusMalware && result.Signature != nil {
		fmt.Printf("Detection: %s\n", result.Signature.DetectionName)
		fmt.Printf("Threat:    %s (%s)\n", result.Signature.ThreatType, result.Signature.Severity)
		fmt.Printf("Source:    %s\n", result.Signature.Source)
	}

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
	}

	fmt.Printf("Lookup:  %.3fms (bloom=%v)\n", result.LookupTimeMs, result.BloomHit)
	fmt.Println()
}

// CombinedScanResult holds results from both ClamAV and Trivy scans.
type CombinedScanResult struct {
	ClamAV *ClamAVSummary    `json:"clamav"`
	Trivy  *trivy.ScanResult `json:"trivy,omitempty"`
}

// ClamAVSummary holds ClamAV scan results and summary.
type ClamAVSummary struct {
	Results  []*types.ScanResult `json:"results"`
	Clean    int                 `json:"clean"`
	Infected int                 `json:"infected"`
	Errors   int                 `json:"errors"`
}

func scanWithClamAV(ctx context.Context, path string, recursive bool, cfg *config.ClamAVConfig, dataDir string, outputJSON, persistMalware, withDeps bool, trivyServer string) error {
	// Check if path exists.
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("accessing path: %w", err)
	}

	// Create scanner.
	clamScanner := scanner.NewClamAVScanner(cfg)

	// Check if clamscan is available.
	if err := clamScanner.Ping(ctx); err != nil {
		return fmt.Errorf("clamscan not available: %w (install ClamAV or check PATH)", err)
	}

	var results []*types.ScanResult

	if info.IsDir() {
		// Scan directory.
		results, err = clamScanner.ScanDir(ctx, path, recursive)
		if err != nil {
			return fmt.Errorf("scanning directory: %w", err)
		}
	} else {
		// Scan single file.
		result, err := clamScanner.ScanFile(ctx, path)
		if err != nil {
			return fmt.Errorf("scanning file: %w", err)
		}
		results = []*types.ScanResult{result}
	}

	// Run Trivy dependency scan if requested.
	var trivyResult *trivy.ScanResult
	if withDeps {
		trivyResult, err = runDependencyScan(ctx, path, trivyServer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: dependency scan failed: %v\n", err)
		}
	}

	// Persist malware detections if requested.
	var persisted int
	if persistMalware {
		eng, err := engine.NewEngine(engine.EngineConfig{
			StoreConfig: engine.StoreConfig{Path: dataDir},
			BloomConfig: engine.BloomConfig{
				ExpectedItems:     10_000_000,
				FalsePositiveRate: 0.001,
			},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open engine for persistence: %v\n", err)
		} else {
			defer eng.Close()

			for _, result := range results {
				if sig := result.ToSignature(); sig != nil {
					if err := eng.AddSignature(ctx, sig); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to persist signature: %v\n", err)
					} else {
						persisted++
					}
				}
			}
		}
	}

	// Calculate ClamAV summary.
	var clean, infected, scanErrors int
	for _, r := range results {
		switch r.Status {
		case types.ScanStatusClean:
			clean++
		case types.ScanStatusInfected:
			infected++
		case types.ScanStatusError:
			scanErrors++
		}
	}

	// Output results.
	if outputJSON {
		combined := CombinedScanResult{
			ClamAV: &ClamAVSummary{
				Results:  results,
				Clean:    clean,
				Infected: infected,
				Errors:   scanErrors,
			},
			Trivy: trivyResult,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(combined)
	}

	// Print human-readable ClamAV output.
	fmt.Println("=========== CLAMAV MALWARE SCAN ===========")
	for _, result := range results {
		printScanResult(result)
	}

	fmt.Println("----------- CLAMAV SUMMARY -----------")
	fmt.Printf("Scanned:  %d files\n", len(results))
	fmt.Printf("Clean:    %d\n", clean)
	fmt.Printf("Infected: %d\n", infected)
	if scanErrors > 0 {
		fmt.Printf("Errors:   %d\n", scanErrors)
	}
	if persisted > 0 {
		fmt.Printf("Persisted: %d signatures\n", persisted)
	}

	// Print Trivy results if available.
	if trivyResult != nil {
		fmt.Println()
		printTrivyCombinedResult(trivyResult)
	}

	return nil
}

func printScanResult(result *types.ScanResult) {
	fmt.Printf("File:   %s\n", result.FilePath)
	fmt.Printf("Status: %s\n", result.Status)

	if result.Status == types.ScanStatusInfected {
		fmt.Printf("Detection: %s\n", result.Detection)
		fmt.Printf("Threat:    %s (%s)\n", result.ThreatType, result.Severity)
	}

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
	}

	if result.FileHash != "" {
		fmt.Printf("SHA256: %s\n", result.FileHash)
	}
	fmt.Printf("Scan:   %.3fms\n", result.ScanTimeMs)
	fmt.Println()
}

func readHashesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			hashes = append(hashes, line)
		}
	}

	return hashes, sc.Err()
}

// runDependencyScan scans a path for dependency vulnerabilities and secrets.
// Uses server mode if trivyServer is provided, otherwise uses local mode.
func runDependencyScan(ctx context.Context, path string, trivyServer string) (*trivy.ScanResult, error) {
	// Determine mode based on server URL.
	var cfg *config.TrivyConfig
	if trivyServer != "" {
		cfg = &config.TrivyConfig{
			Mode:      "server",
			ServerURL: trivyServer,
			Timeout:   2 * time.Minute,
		}
	} else {
		cfg = &config.TrivyConfig{
			Mode:    "local",
			Binary:  "trivy",
			Timeout: 5 * time.Minute,
		}
	}

	// Create unified scanner.
	scanner := trivy.NewUnifiedScanner(cfg)

	// Scan with HIGH/CRITICAL filter and secrets.
	opts := trivy.ScanOptions{
		SeverityFilter: []string{trivy.SeverityCritical, trivy.SeverityHigh},
		ScanSecrets:    true,
	}

	return scanner.ScanPath(ctx, path, opts)
}

// printTrivyCombinedResult prints Trivy scan results in human-readable format.
func printTrivyCombinedResult(result *trivy.ScanResult) {
	fmt.Println("=========== TRIVY DEPENDENCY SCAN ===========")
	fmt.Printf("Packages Scanned: %d\n", result.Summary.PackagesScanned)
	fmt.Printf("Scan Time:        %.2fms\n", result.ScanTimeMs)
	fmt.Println()

	// Print vulnerability summary.
	if result.Summary.TotalVulnerabilities == 0 {
		fmt.Println("No vulnerabilities found.")
	} else {
		fmt.Println("----------- VULNERABILITY SUMMARY -----------")
		fmt.Printf("Total:    %d\n", result.Summary.TotalVulnerabilities)
		if result.Summary.Critical > 0 {
			fmt.Printf("Critical: %d\n", result.Summary.Critical)
		}
		if result.Summary.High > 0 {
			fmt.Printf("High:     %d\n", result.Summary.High)
		}
		if result.Summary.Medium > 0 {
			fmt.Printf("Medium:   %d\n", result.Summary.Medium)
		}
		if result.Summary.Low > 0 {
			fmt.Printf("Low:      %d\n", result.Summary.Low)
		}
		fmt.Println()

		fmt.Println("----------- VULNERABILITIES -----------")
		for _, vuln := range result.Vulnerabilities {
			fmt.Printf("\n%s [%s]\n", vuln.CVEID, vuln.Severity)
			fmt.Printf("  Package: %s@%s (%s)\n", vuln.Package, vuln.Version, vuln.Ecosystem)
			if vuln.Title != "" {
				fmt.Printf("  Title:   %s\n", vuln.Title)
			}
			if vuln.FixedVersion != "" {
				fmt.Printf("  Fixed:   %s\n", vuln.FixedVersion)
			}
		}
	}

	// Print secret summary.
	if result.SecretSummary != nil && result.SecretSummary.TotalSecrets > 0 {
		fmt.Println()
		fmt.Println("----------- SECRET SUMMARY -----------")
		fmt.Printf("Total:    %d\n", result.SecretSummary.TotalSecrets)
		if result.SecretSummary.Critical > 0 {
			fmt.Printf("Critical: %d\n", result.SecretSummary.Critical)
		}
		if result.SecretSummary.High > 0 {
			fmt.Printf("High:     %d\n", result.SecretSummary.High)
		}
		if result.SecretSummary.Medium > 0 {
			fmt.Printf("Medium:   %d\n", result.SecretSummary.Medium)
		}
		if result.SecretSummary.Low > 0 {
			fmt.Printf("Low:      %d\n", result.SecretSummary.Low)
		}
		fmt.Println()

		fmt.Println("----------- SECRETS -----------")
		for _, secret := range result.Secrets {
			fmt.Printf("\n%s [%s]\n", secret.RuleID, secret.Severity)
			fmt.Printf("  Category: %s\n", secret.Category)
			fmt.Printf("  Title:    %s\n", secret.Title)
			if secret.Target != "" {
				fmt.Printf("  Target:   %s\n", secret.Target)
			}
			if secret.StartLine > 0 {
				fmt.Printf("  Lines:    %d-%d\n", secret.StartLine, secret.EndLine)
			}
		}
	}

	fmt.Println()
}
