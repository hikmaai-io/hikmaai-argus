// ABOUTME: Feed management commands for signature updates
// ABOUTME: Provides list, update, and import operations

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikma-av/internal/config"
	"github.com/hikmaai-io/hikma-av/internal/engine"
	"github.com/hikmaai-io/hikma-av/internal/feeds"
	"github.com/hikmaai-io/hikma-av/internal/types"
)

func newFeedsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feeds",
		Short: "Manage signature feeds",
		Long:  `Commands for managing signature feeds (ClamAV, abuse.ch, etc.).`,
	}

	cmd.AddCommand(newFeedsListCmd())
	cmd.AddCommand(newFeedsUpdateCmd())
	cmd.AddCommand(newFeedsImportCmd())

	return cmd
}

func newFeedsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured feeds and their status",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Available feeds:")
			fmt.Println("  eicar    - EICAR test signatures (built-in, always available)")
			fmt.Println("  clamav   - ClamAV main.cvd and daily.cvd (not yet implemented)")
			fmt.Println("  abusech  - abuse.ch malware bazaar feed (not yet implemented)")
			fmt.Println()
			fmt.Println("Use 'hikma-av feeds update' to load the EICAR signatures into the database.")
		},
	}
}

func newFeedsUpdateCmd() *cobra.Command {
	var (
		dataDir string
		source  string
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Load signatures into the database",
		Long: `Load signatures from configured feeds into the database.

Currently supported feeds:
  eicar  - Built-in EICAR test signatures (default)

Example:
  hikma-av feeds update              # Load EICAR signatures
  hikma-av feeds update --source eicar`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFeedsUpdate(cmd.Context(), dataDir, source)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for BadgerDB")
	cmd.Flags().StringVar(&source, "source", "eicar", "feed source to load (eicar)")

	return cmd
}

func runFeedsUpdate(ctx context.Context, dataDir, source string) error {
	fmt.Printf("Loading signatures from '%s' feed...\n", source)

	// Ensure data directory exists.
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("failed to create data directory %s: %w", dataDir, err)
	}

	// Create engine.
	eng, err := engine.NewEngine(engine.EngineConfig{
		StoreConfig: engine.StoreConfig{
			Path: dataDir,
		},
		BloomConfig: engine.BloomConfig{
			ExpectedItems:     10_000_000,
			FalsePositiveRate: 0.001,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer eng.Close()

	var sigs []*types.Signature

	switch strings.ToLower(source) {
	case "eicar":
		sigs = feeds.EICARSignatures()
	default:
		return fmt.Errorf("unknown feed source: %s (available: eicar)", source)
	}

	if len(sigs) == 0 {
		fmt.Println("No signatures to load.")
		return nil
	}

	// Convert feeds.Signature to types.Signature and add to engine.
	if err := eng.BatchAddSignatures(ctx, sigs); err != nil {
		return fmt.Errorf("failed to add signatures to database: %w", err)
	}

	// Rebuild bloom filter.
	fmt.Println("Rebuilding bloom filter...")
	if err := eng.RebuildBloomFilter(ctx); err != nil {
		return fmt.Errorf("failed to rebuild bloom filter: %w", err)
	}

	fmt.Printf("Successfully loaded %d signatures into %s\n", len(sigs), dataDir)

	// Show stats.
	stats, err := eng.Stats(ctx)
	if err == nil {
		fmt.Printf("Database now contains %d signatures\n", stats.SignatureCount)
	}

	return nil
}


func newFeedsImportCmd() *cobra.Command {
	var (
		feedType string
		dataDir  string
	)

	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import a feed file manually",
		Long: `Import signatures from a file into the database.

Supported formats:
  csv    - CSV file with hash columns (abuse.ch format)

Example:
  hikma-av feeds import --type csv hashes.csv`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFeedsImport(cmd.Context(), args[0], feedType, dataDir)
		},
	}

	cmd.Flags().StringVarP(&feedType, "type", "t", "csv", "feed type (csv)")
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for BadgerDB")

	return cmd
}

func runFeedsImport(ctx context.Context, filePath, feedType, dataDir string) error {
	fmt.Printf("Importing signatures from %s (type=%s)...\n", filePath, feedType)

	// Open the file.
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Ensure data directory exists.
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Create engine.
	eng, err := engine.NewEngine(engine.EngineConfig{
		StoreConfig: engine.StoreConfig{
			Path: dataDir,
		},
		BloomConfig: engine.BloomConfig{
			ExpectedItems:     10_000_000,
			FalsePositiveRate: 0.001,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer eng.Close()

	// Parse the feed.
	var sigs []*types.Signature

	switch strings.ToLower(feedType) {
	case "csv":
		csvFeed := feeds.NewCSVFeed("import", feeds.CSVConfig{
			SHA256Column: 0,
			SkipHeader:   true,
			CommentChar:  '#',
		})
		sigs, err = csvFeed.Parse(ctx, file)
		if err != nil {
			return fmt.Errorf("failed to parse CSV: %w", err)
		}
	default:
		return fmt.Errorf("unsupported feed type: %s (available: csv)", feedType)
	}

	if len(sigs) == 0 {
		fmt.Println("No valid signatures found in file.")
		return nil
	}

	// Add signatures.
	if err := eng.BatchAddSignatures(ctx, sigs); err != nil {
		return fmt.Errorf("failed to add signatures: %w", err)
	}

	// Rebuild bloom filter.
	fmt.Println("Rebuilding bloom filter...")
	if err := eng.RebuildBloomFilter(ctx); err != nil {
		return fmt.Errorf("failed to rebuild bloom filter: %w", err)
	}

	fmt.Printf("Successfully imported %d signatures\n", len(sigs))

	return nil
}
