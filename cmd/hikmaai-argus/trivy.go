// ABOUTME: Trivy subcommand for dependency vulnerability scanning
// ABOUTME: Supports local CLI and remote server modes for vulnerability and secret scanning

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikmaai-argus/internal/config"
	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
)

func newTrivyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trivy",
		Short: "Trivy dependency vulnerability scanner",
		Long: `Scan dependencies for known vulnerabilities and secrets using Trivy.

Supports two modes:
- local: Uses the local trivy binary (default, requires trivy installed)
- server: Connects to a remote Trivy server via Twirp protocol

Default severity filter: HIGH, CRITICAL
Default: Also scans for secrets

Examples:
  # Scan a directory (local mode, default)
  hikmaai-argus trivy scan /path/to/project

  # Scan an archive
  hikmaai-argus trivy scan /path/to/app.zip

  # Scan with server mode
  hikmaai-argus trivy scan --mode server --server http://trivy:4954 /path/to/project

  # Scan specific packages (server mode only)
  hikmaai-argus trivy scan --mode server --server http://trivy:4954 --packages "requests:2.25.0:pip"

  # Output as JSON
  hikmaai-argus trivy scan /path/to/project --json`,
	}

	cmd.AddCommand(newTrivyScanCmd())

	return cmd
}

func newTrivyScanCmd() *cobra.Command {
	var (
		mode           string
		packages       string
		serverURL      string
		binary         string
		severityFilter string
		scanSecrets    bool
		skipDBUpdate   bool
		timeout        time.Duration
		outputJSON     bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan for vulnerabilities and secrets",
		Long: `Scan a directory or archive for known vulnerabilities and secrets.

LOCAL MODE (default):
  Uses the local trivy binary to scan the filesystem directly.
  Requires trivy to be installed (brew install trivy, apt install trivy, etc.)

SERVER MODE:
  Extracts package metadata and sends to remote Trivy server via Twirp.
  Use --packages to scan specific packages without a path.

Default filters: HIGH, CRITICAL vulnerabilities + secrets

Package format (for --packages): "name:version:ecosystem" separated by commas.
Supported ecosystems: pip, npm, gomod, cargo, composer, maven, nuget, rubygems

Examples:
  # Local mode (default) - scan directory
  hikmaai-argus trivy scan /path/to/project

  # Local mode - scan archive
  hikmaai-argus trivy scan /path/to/app.zip

  # Server mode - scan path
  hikmaai-argus trivy scan --mode server --server http://trivy:4954 /path/to/project

  # Server mode - scan specific packages
  hikmaai-argus trivy scan --mode server --server http://trivy:4954 --packages "requests:2.25.0:pip"`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Parse severity filter (default: HIGH, CRITICAL).
			sevFilter := parseSeverityFilter(severityFilter)
			if sevFilter == nil {
				sevFilter = []string{trivy.SeverityCritical, trivy.SeverityHigh}
			}

			opts := trivy.ScanOptions{
				SeverityFilter: sevFilter,
				ScanSecrets:    scanSecrets,
			}

			// Validate mode-specific requirements.
			if mode == "server" {
				if serverURL == "" {
					return fmt.Errorf("--server is required for server mode")
				}
				return runTrivyServerScan(ctx, args, serverURL, packages, opts, timeout, outputJSON)
			}

			// Local mode.
			if len(args) == 0 {
				return fmt.Errorf("path is required for local mode")
			}

			return runTrivyLocalScan(ctx, args[0], binary, skipDBUpdate, opts, timeout, outputJSON)
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "local", "scanner mode: local (default) or server")
	cmd.Flags().StringVar(&serverURL, "server", "", "Trivy server URL (required for server mode)")
	cmd.Flags().StringVar(&binary, "binary", "trivy", "path to trivy binary (local mode)")
	cmd.Flags().StringVarP(&packages, "packages", "p", "", "comma-separated packages (name:version:ecosystem) for server mode")
	cmd.Flags().StringVar(&severityFilter, "severity", "", "severity filter (default: HIGH,CRITICAL)")
	cmd.Flags().BoolVar(&scanSecrets, "secrets", true, "scan for secrets (default: true)")
	cmd.Flags().BoolVar(&skipDBUpdate, "skip-db-update", false, "skip updating vulnerability database (local mode)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "scan timeout")
	cmd.Flags().BoolVarP(&outputJSON, "json", "j", false, "output as JSON")

	return cmd
}

func parseSeverityFilter(severityFilter string) []string {
	if severityFilter == "" {
		return nil
	}

	var sevFilter []string
	for _, s := range strings.Split(severityFilter, ",") {
		s = strings.TrimSpace(strings.ToUpper(s))
		if s != "" && trivy.IsValidSeverity(s) {
			sevFilter = append(sevFilter, s)
		}
	}
	return sevFilter
}

func runTrivyLocalScan(ctx context.Context, path, binary string, skipDBUpdate bool, opts trivy.ScanOptions, timeout time.Duration, outputJSON bool) error {
	// Create local scanner.
	scanner := trivy.NewUnifiedScanner(&config.TrivyConfig{
		Mode:         "local",
		Binary:       binary,
		SkipDBUpdate: skipDBUpdate,
		Timeout:      timeout,
	})

	// Check if trivy is available.
	if err := scanner.Ping(ctx); err != nil {
		return fmt.Errorf("trivy not available: %w (install with: brew install trivy)", err)
	}

	// Run scan.
	result, err := scanner.ScanPath(ctx, path, opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	return outputTrivyResult(result, outputJSON)
}

func runTrivyServerScan(ctx context.Context, args []string, serverURL, packages string, opts trivy.ScanOptions, timeout time.Duration, outputJSON bool) error {
	// Create server scanner.
	scanner := trivy.NewUnifiedScanner(&config.TrivyConfig{
		Mode:      "server",
		ServerURL: serverURL,
		Timeout:   timeout,
	})

	var result *trivy.ScanResult
	var err error

	if packages != "" {
		// Scan specific packages.
		pkgs, err := parsePackages(packages)
		if err != nil {
			return err
		}
		result, err = scanner.ScanPackagesWithOptions(ctx, pkgs, opts)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
	} else if len(args) > 0 {
		// Scan path.
		result, err = scanner.ScanPath(ctx, args[0], opts)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
	} else {
		return fmt.Errorf("either path or --packages is required")
	}

	return outputTrivyResult(result, outputJSON)
}

func outputTrivyResult(result *trivy.ScanResult, outputJSON bool) error {
	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	printTrivyResult(result)
	return nil
}

func parsePackages(input string) ([]trivy.Package, error) {
	var pkgs []trivy.Package

	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		fields := strings.Split(part, ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid package format %q; expected name:version:ecosystem", part)
		}

		pkg := trivy.Package{
			Name:      fields[0],
			Version:   fields[1],
			Ecosystem: fields[2],
		}

		if err := pkg.Validate(); err != nil {
			return nil, fmt.Errorf("invalid package %q: %w", part, err)
		}

		pkgs = append(pkgs, pkg)
	}

	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no valid packages provided")
	}

	return pkgs, nil
}

func printTrivyResult(result *trivy.ScanResult) {
	fmt.Println("=========== TRIVY DEPENDENCY SCAN ===========")
	fmt.Printf("Packages Scanned: %d\n", result.Summary.PackagesScanned)
	fmt.Printf("Scan Time:        %.2fms\n", result.ScanTimeMs)
	fmt.Println()

	// Vulnerability summary.
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

	// Secret summary.
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
	} else {
		fmt.Println()
		fmt.Println("No secrets found.")
	}

	fmt.Println()
}
