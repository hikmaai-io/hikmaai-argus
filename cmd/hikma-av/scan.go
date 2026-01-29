// ABOUTME: Scan command for checking hashes against the signature database
// ABOUTME: Supports single hash, file input, and batch modes

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikma-av/internal/config"
	"github.com/hikmaai-io/hikma-av/internal/engine"
	"github.com/hikmaai-io/hikma-av/internal/types"
)

func newScanCmd() *cobra.Command {
	var (
		fileInput   string
		batch       string
		direct      bool
		nats        bool
		outputJSON  bool
		dataDir     string
	)

	cmd := &cobra.Command{
		Use:   "scan [hash]",
		Short: "Scan a hash for malware signatures",
		Long: `Scan one or more hashes against the signature database.

By default, the scan command will:
1. Try to connect to a running daemon via NATS
2. Fall back to direct database access if no daemon is running

Use --direct to force direct database access (no NATS).
Use --nats to force NATS (fail if no daemon).

Examples:
  hikma-av scan 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  hikma-av scan --file hashes.txt
  hikma-av scan --batch "hash1,hash2,hash3"`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Collect hashes to scan.
			var hashes []string

			if len(args) > 0 {
				hashes = append(hashes, args[0])
			}

			if fileInput != "" {
				fileHashes, err := readHashesFromFile(fileInput)
				if err != nil {
					return fmt.Errorf("failed to read hashes from file: %w", err)
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
				return fmt.Errorf("no hashes provided; use positional argument, --file, or --batch")
			}

			// Determine scan mode.
			if nats && direct {
				return fmt.Errorf("cannot use both --nats and --direct")
			}

			// For now, always use direct mode until NATS is implemented.
			return scanDirect(cmd.Context(), hashes, dataDir, outputJSON)
		},
	}

	cmd.Flags().StringVarP(&fileInput, "file", "f", "", "file containing hashes (one per line)")
	cmd.Flags().StringVarP(&batch, "batch", "b", "", "comma-separated list of hashes")
	cmd.Flags().BoolVar(&direct, "direct", false, "force direct database access (skip NATS check)")
	cmd.Flags().BoolVar(&nats, "nats", false, "force NATS (fail if no daemon)")
	cmd.Flags().BoolVarP(&outputJSON, "json", "j", false, "output results as JSON")
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for BadgerDB")

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
