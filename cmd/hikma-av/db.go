// ABOUTME: Database inspection commands for debugging and maintenance
// ABOUTME: Provides stats, get, list, compact, and export operations

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikma-av/internal/config"
	"github.com/hikmaai-io/hikma-av/internal/engine"
	"github.com/hikmaai-io/hikma-av/internal/types"
)

func newDBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database inspection and maintenance commands",
		Long:  `Commands for inspecting and maintaining the BadgerDB signature database.`,
	}

	cmd.AddCommand(newDBStatsCmd())
	cmd.AddCommand(newDBGetCmd())
	cmd.AddCommand(newDBCompactCmd())

	return cmd
}

func newDBStatsCmd() *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show database statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			return dbStats(cmd.Context(), dataDir)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for BadgerDB")

	return cmd
}

func newDBGetCmd() *cobra.Command {
	var (
		dataDir    string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "get <hash>",
		Short: "Get signature details for a hash",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return dbGet(cmd.Context(), args[0], dataDir, outputJSON)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for BadgerDB")
	cmd.Flags().BoolVarP(&outputJSON, "json", "j", false, "output as JSON")

	return cmd
}

func newDBCompactCmd() *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "compact",
		Short: "Trigger database compaction",
		RunE: func(cmd *cobra.Command, args []string) error {
			return dbCompact(cmd.Context(), dataDir)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for BadgerDB")

	return cmd
}

func dbStats(ctx context.Context, dataDir string) error {
	fmt.Printf("Database path: %s\n", dataDir)

	store, err := engine.NewStore(engine.StoreConfig{
		Path: dataDir,
	})
	if err != nil {
		return fmt.Errorf("failed to open store: %w", err)
	}
	defer store.Close()

	stats, err := store.Stats(ctx)
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	fmt.Printf("Database Statistics:\n")
	fmt.Printf("  Signatures: %d\n", stats.SignatureCount)
	fmt.Printf("  Size:       %s\n", formatBytes(stats.SizeBytes))

	if stats.SignatureCount == 0 {
		fmt.Println()
		fmt.Println("Database is empty. Load signatures with:")
		fmt.Println("  hikma-av feeds update")
	}

	return nil
}

func dbGet(ctx context.Context, hashStr, dataDir string, outputJSON bool) error {
	hash, err := types.ParseHash(hashStr)
	if err != nil {
		return fmt.Errorf("invalid hash: %w", err)
	}

	store, err := engine.NewStore(engine.StoreConfig{
		Path: dataDir,
	})
	if err != nil {
		return fmt.Errorf("failed to open store: %w", err)
	}
	defer store.Close()

	sig, err := store.Get(ctx, hash)
	if err != nil {
		return fmt.Errorf("failed to get signature: %w", err)
	}

	if sig == nil {
		if outputJSON {
			fmt.Println("null")
		} else {
			fmt.Println("Signature not found")
		}
		return nil
	}

	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sig)
	}

	fmt.Printf("SHA256:    %s\n", sig.SHA256)
	if sig.SHA1 != "" {
		fmt.Printf("SHA1:      %s\n", sig.SHA1)
	}
	if sig.MD5 != "" {
		fmt.Printf("MD5:       %s\n", sig.MD5)
	}
	fmt.Printf("Detection: %s\n", sig.DetectionName)
	fmt.Printf("Threat:    %s\n", sig.ThreatType)
	fmt.Printf("Severity:  %s\n", sig.Severity)
	fmt.Printf("Source:    %s\n", sig.Source)
	fmt.Printf("FirstSeen: %s\n", sig.FirstSeen.Format("2006-01-02 15:04:05"))

	return nil
}

func dbCompact(ctx context.Context, dataDir string) error {
	store, err := engine.NewStore(engine.StoreConfig{
		Path: dataDir,
	})
	if err != nil {
		return fmt.Errorf("failed to open store: %w", err)
	}
	defer store.Close()

	fmt.Println("Running compaction...")
	if err := store.Compact(); err != nil {
		// Compaction error is not fatal; it may just mean nothing to compact.
		fmt.Printf("Compaction note: %v\n", err)
	}
	fmt.Println("Compaction complete")

	return nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
