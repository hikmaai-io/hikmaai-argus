// ABOUTME: Scan command for checking hashes against the signature database
// ABOUTME: Supports single hash, file input, batch modes, and ClamAV file scanning

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikma-av/internal/config"
	"github.com/hikmaai-io/hikma-av/internal/engine"
	"github.com/hikmaai-io/hikma-av/internal/scanner"
	"github.com/hikmaai-io/hikma-av/internal/types"
)

func newScanCmd() *cobra.Command {
	var (
		fileInput     string
		batch         string
		direct        bool
		nats          bool
		outputJSON    bool
		dataDir       string
		withFile      string
		recursive     bool
		clamdAddress  string
		persistMalware bool
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
  hikma-av scan 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  hikma-av scan --file hashes.txt
  hikma-av scan --batch "hash1,hash2,hash3"

  # File scanning with ClamAV
  hikma-av scan --with-file /path/to/suspicious.exe
  hikma-av scan --with-file /path/to/directory --recursive
  hikma-av scan --with-file /path/to/file.exe --persist  # Save detections to DB`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// File scan mode.
			if withFile != "" {
				cfg := &config.ClamAVConfig{
					Mode:        "clamscan",
					Binary:      "clamscan",
					DatabaseDir: filepath.Join(dataDir, "clamav"),
					Address:     clamdAddress,
					Timeout:     5 * time.Minute,
				}
				return scanWithClamAV(ctx, withFile, recursive, cfg, dataDir, outputJSON, persistMalware)
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
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for BadgerDB")

	// ClamAV file scanning flags.
	cmd.Flags().StringVar(&withFile, "with-file", "", "path to file or directory to scan with ClamAV")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "scan directories recursively")
	cmd.Flags().StringVar(&clamdAddress, "clamd-address", "", "clamd address (for clamd mode)")
	cmd.Flags().BoolVar(&persistMalware, "persist", false, "persist malware detections to signature database")

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

func scanWithClamAV(ctx context.Context, path string, recursive bool, cfg *config.ClamAVConfig, dataDir string, outputJSON, persistMalware bool) error {
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

	// Output results.
	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	// Print human-readable output.
	for _, result := range results {
		printScanResult(result)
	}

	// Print summary.
	var clean, infected, errors int
	for _, r := range results {
		switch r.Status {
		case types.ScanStatusClean:
			clean++
		case types.ScanStatusInfected:
			infected++
		case types.ScanStatusError:
			errors++
		}
	}

	fmt.Println("----------- SCAN SUMMARY -----------")
	fmt.Printf("Scanned:  %d files\n", len(results))
	fmt.Printf("Clean:    %d\n", clean)
	fmt.Printf("Infected: %d\n", infected)
	if errors > 0 {
		fmt.Printf("Errors:   %d\n", errors)
	}
	if persisted > 0 {
		fmt.Printf("Persisted: %d signatures\n", persisted)
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
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			hashes = append(hashes, line)
		}
	}

	return hashes, scanner.Err()
}
