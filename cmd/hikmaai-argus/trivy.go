// ABOUTME: Trivy subcommand for dependency vulnerability scanning
// ABOUTME: Supports scanning packages via Trivy server

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
)

func newTrivyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trivy",
		Short: "Trivy dependency vulnerability scanner",
		Long: `Scan dependencies for known vulnerabilities using Trivy server.

Trivy uses a remote server to check package metadata against vulnerability databases.
Only package names and versions are sent; no source code or file contents.

Examples:
  # Scan packages
  hikmaai-argus trivy scan --packages "requests:2.25.0:pip,lodash:4.17.20:npm"

  # Scan with severity filter
  hikmaai-argus trivy scan --packages "requests:2.25.0:pip" --severity "HIGH,CRITICAL"

  # Output as JSON
  hikmaai-argus trivy scan --packages "requests:2.25.0:pip" --json`,
	}

	cmd.AddCommand(newTrivyScanCmd())

	return cmd
}

func newTrivyScanCmd() *cobra.Command {
	var (
		packages       string
		serverURL      string
		severityFilter string
		timeout        time.Duration
		outputJSON     bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan packages for vulnerabilities",
		Long: `Scan packages for known vulnerabilities via Trivy server.

Package format: "name:version:ecosystem" separated by commas.
Supported ecosystems: pip, npm, gomod, cargo, composer, maven, nuget, rubygems

Examples:
  hikmaai-argus trivy scan --server http://trivy:4954 --packages "requests:2.25.0:pip"
  hikmaai-argus trivy scan --packages "requests:2.25.0:pip,lodash:4.17.20:npm"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if serverURL == "" {
				return fmt.Errorf("--server is required")
			}
			if packages == "" {
				return fmt.Errorf("--packages is required")
			}

			// Parse packages.
			pkgs, err := parsePackages(packages)
			if err != nil {
				return err
			}

			// Parse severity filter.
			var sevFilter []string
			if severityFilter != "" {
				for _, s := range strings.Split(severityFilter, ",") {
					s = strings.TrimSpace(strings.ToUpper(s))
					if s != "" {
						if !trivy.IsValidSeverity(s) {
							return fmt.Errorf("invalid severity: %s", s)
						}
						sevFilter = append(sevFilter, s)
					}
				}
			}

			return runTrivyScan(cmd.Context(), serverURL, pkgs, sevFilter, timeout, outputJSON)
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "", "Trivy server URL (required)")
	cmd.Flags().StringVarP(&packages, "packages", "p", "", "comma-separated packages (name:version:ecosystem)")
	cmd.Flags().StringVar(&severityFilter, "severity", "", "severity filter (e.g., HIGH,CRITICAL)")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "scan timeout")
	cmd.Flags().BoolVarP(&outputJSON, "json", "j", false, "output as JSON")

	return cmd
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

func runTrivyScan(ctx context.Context, serverURL string, packages []trivy.Package, severityFilter []string, timeout time.Duration, outputJSON bool) error {
	// Create scanner (no cache for CLI mode).
	scanner := trivy.NewScanner(trivy.ScannerConfig{
		ServerURL: serverURL,
		Timeout:   timeout,
	})

	// Run scan.
	result, err := scanner.ScanPackages(ctx, packages, severityFilter)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results.
	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Print human-readable output.
	printTrivyResult(result)

	return nil
}

func printTrivyResult(result *trivy.ScanResult) {
	fmt.Println("----------- VULNERABILITY SCAN -----------")
	fmt.Printf("Packages Scanned: %d\n", result.Summary.PackagesScanned)
	fmt.Printf("Scan Time:        %.2fms\n", result.ScanTimeMs)
	fmt.Println()

	if result.Summary.TotalVulnerabilities == 0 {
		fmt.Println("No vulnerabilities found.")
		return
	}

	fmt.Println("----------- SUMMARY -----------")
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
	fmt.Println()
}
