// ABOUTME: Feed management commands for signature updates
// ABOUTME: Provides list, update, and import operations for multiple feed sources

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikmaai-argus/internal/config"
	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/feeds"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func newFeedsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feeds",
		Short: "Manage signature feeds",
		Long:  `Commands for managing signature feeds (ClamAV, MalwareBazaar, ThreatFox, etc.).`,
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
			fmt.Println()
			fmt.Println("ClamAV Database Feed (for clamscan file analysis) → data/clamdb:")
			fmt.Println("  clamav-db     - Downloads CVD files for clamscan (main.cvd, daily.cvd)")
			fmt.Println()
			fmt.Println("Hash Signature Feeds (for bloom + BadgerDB lookup) → data/hikmaaidb:")
			fmt.Println("  eicar         - EICAR test signature (built-in, quick test)")
			fmt.Println("  malwarebazaar - abuse.ch MalwareBazaar SHA256 hash list (~1M hashes)")
			fmt.Println("  clamav        - ClamAV signature hashes (extracts from CVD files)")
			fmt.Println("  threatfox     - abuse.ch ThreatFox IOC feed (mostly URLs/IPs, few hashes)")
			fmt.Println("  urlhaus       - abuse.ch URLhaus (URL-based, no file hashes)")
			fmt.Println()
			fmt.Println("Meta source:")
			fmt.Println("  all           - Load clamav-db + eicar + malwarebazaar + clamav (DEFAULT)")
			fmt.Println()
			fmt.Println("Usage:")
			fmt.Println("  hikmaai-argus feeds update                        # Load all feeds (default)")
			fmt.Println("  hikmaai-argus feeds update --source clamav-db     # ClamAV databases only")
			fmt.Println("  hikmaai-argus feeds update --source eicar         # EICAR signatures only")
			fmt.Println("  hikmaai-argus feeds update --source malwarebazaar # MalwareBazaar hashes only")
		},
	}
}

func newFeedsUpdateCmd() *cobra.Command {
	var (
		dataDir      string
		clamDBDir    string
		source       string
		reloadClamd  bool
		clamdAddress string
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Load signatures into the database",
		Long: `Load signatures from configured feeds into the database.

Supported feeds:
  all           - Load all feeds (default): clamav-db + eicar + malwarebazaar + clamav
  clamav-db     - ClamAV database files (main.cvd, daily.cvd) → data/clamdb
  eicar         - Built-in EICAR test signatures → data/hikmaaidb
  clamav        - ClamAV signature hashes (extracts from CVD) → data/hikmaaidb
  malwarebazaar - abuse.ch MalwareBazaar SHA256 hash list → data/hikmaaidb
  threatfox     - abuse.ch ThreatFox IOC feed → data/hikmaaidb

Example:
  hikmaai-argus feeds update                        # Load all feeds (default)
  hikmaai-argus feeds update --source clamav-db     # ClamAV databases only
  hikmaai-argus feeds update --source eicar         # EICAR test signatures only
  hikmaai-argus feeds update --source malwarebazaar # MalwareBazaar hashes only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFeedsUpdate(cmd.Context(), dataDir, clamDBDir, source, reloadClamd, clamdAddress)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for HikmaAI signatures")
	cmd.Flags().StringVar(&clamDBDir, "clamdb-dir", config.DefaultClamDBDir(), "directory for ClamAV databases (CVD files)")
	cmd.Flags().StringVar(&source, "source", "all", "feed source to load (eicar, clamav, clamav-db, malwarebazaar, threatfox, all)")
	cmd.Flags().BoolVar(&reloadClamd, "reload-clamd", false, "send RELOAD command to clamd after updating CVD files")
	cmd.Flags().StringVar(&clamdAddress, "clamd-address", "", "clamd address for reload (unix:// or tcp://)")

	return cmd
}

func runFeedsUpdate(ctx context.Context, dataDir, clamDBDir, source string, reloadClamd bool, clamdAddress string) error {
	sources := parseSources(source)

	// Handle clamav-db separately (doesn't return signatures, manages CVD files).
	var cvdUpdated bool
	for i, src := range sources {
		if src == "clamav-db" {
			updated, err := updateClamAVDB(ctx, clamDBDir)
			if err != nil {
				fmt.Printf("Warning: failed to update clamav-db: %v\n", err)
			} else {
				cvdUpdated = updated
			}
			// Remove from list so it's not processed below.
			sources = append(sources[:i], sources[i+1:]...)
			break
		}
	}

	// Reload clamd if CVD files were updated and --reload-clamd is set.
	if cvdUpdated && reloadClamd {
		fmt.Println("Reloading clamd databases...")
		if err := feeds.ReloadClamd(ctx, clamdAddress); err != nil {
			fmt.Printf("Warning: failed to reload clamd: %v\n", err)
		} else {
			fmt.Println("  clamd reloaded successfully")
		}
	}

	// If no signature feeds to process, we're done.
	if len(sources) == 0 {
		return nil
	}

	// Ensure data directory exists for signature feeds.
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("failed to create data directory %s: %w", dataDir, err)
	}

	// Create engine for signature feeds.
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

	var allSigs []*types.Signature

	for _, src := range sources {
		fmt.Printf("Loading signatures from '%s' feed...\n", src)

		sigs, err := loadFeed(ctx, src, clamDBDir)
		if err != nil {
			fmt.Printf("  Warning: failed to load %s: %v\n", src, err)
			continue
		}

		if len(sigs) > 0 {
			fmt.Printf("  Loaded %d signatures from %s\n", len(sigs), src)
			allSigs = append(allSigs, sigs...)
		} else {
			fmt.Printf("  No signatures loaded from %s\n", src)
		}
	}

	if len(allSigs) == 0 {
		fmt.Println("No signatures to load.")
		return nil
	}

	// Add signatures to engine.
	fmt.Printf("\nAdding %d total signatures to database...\n", len(allSigs))
	if err := eng.BatchAddSignatures(ctx, allSigs); err != nil {
		return fmt.Errorf("failed to add signatures to database: %w", err)
	}

	// Rebuild bloom filter.
	fmt.Println("Rebuilding bloom filter...")
	if err := eng.RebuildBloomFilter(ctx); err != nil {
		return fmt.Errorf("failed to rebuild bloom filter: %w", err)
	}

	fmt.Printf("\nSuccessfully loaded %d signatures into %s\n", len(allSigs), dataDir)

	// Show stats.
	stats, err := eng.Stats(ctx)
	if err == nil {
		fmt.Printf("Database now contains %d signatures\n", stats.SignatureCount)
	}

	return nil
}

// updateClamAVDB downloads ClamAV database files (CVD) for clamscan.
// This works like freshclam: downloads main.cvd and daily.cvd to the specified directory.
// Returns true if any databases were actually downloaded (not skipped).
func updateClamAVDB(ctx context.Context, clamDBDir string) (bool, error) {
	fmt.Printf("Updating ClamAV databases (CVD files) in %s...\n", clamDBDir)

	dbFeed := feeds.NewClamAVDBFeed(clamDBDir)

	stats, err := dbFeed.Update(ctx)
	if err != nil {
		return false, fmt.Errorf("updating ClamAV databases: %w", err)
	}

	fmt.Printf("  ClamAV database update: %s\n", stats)

	versions := dbFeed.GetVersionInfo()
	for db, version := range versions {
		fmt.Printf("  %s: version %d\n", db, version)
	}

	return stats.Downloaded > 0, nil
}

// parseSources parses the source string into a list of feed sources.
func parseSources(source string) []string {
	source = strings.ToLower(strings.TrimSpace(source))

	if source == "all" {
		// Include all useful feeds:
		// - clamav-db: CVD files for clamscan (data/clamdb)
		// - eicar, malwarebazaar, clamav: signature hashes (data/hikmaaidb)
		// ThreatFox and URLhaus primarily provide URLs/IPs, not file hashes.
		return []string{"clamav-db", "eicar", "malwarebazaar", "clamav"}
	}

	// Support comma-separated sources.
	if strings.Contains(source, ",") {
		parts := strings.Split(source, ",")
		var sources []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				sources = append(sources, p)
			}
		}
		return sources
	}

	return []string{source}
}

// loadFeed loads signatures from a specific feed source.
// clamDBDir is used by the clamav feed to read from local CVD files.
func loadFeed(ctx context.Context, source string, clamDBDir string) ([]*types.Signature, error) {
	switch strings.ToLower(source) {
	case "eicar":
		return feeds.EICARSignatures(), nil

	case "clamav":
		// Use local CVD files if they exist (downloaded by clamav-db feed).
		feed := feeds.NewClamAVFeedFromLocal(clamDBDir)
		return feed.Fetch(ctx)

	case "malwarebazaar", "abusech", "abuse.ch":
		feed := feeds.NewMalwareBazaarFeed()
		return feed.Fetch(ctx)

	case "threatfox":
		feed := feeds.NewThreatFoxFeed()
		return feed.Fetch(ctx)

	case "urlhaus":
		feed := feeds.NewURLhausFeed()
		return feed.Fetch(ctx)

	default:
		return nil, fmt.Errorf("unknown feed source: %s (available: eicar, clamav, malwarebazaar, threatfox, urlhaus, all)", source)
	}
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
  hikmaai-argus feeds import --type csv hashes.csv`,
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
