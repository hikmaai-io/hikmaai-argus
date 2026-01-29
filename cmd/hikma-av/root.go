// ABOUTME: Root command for hikma-av CLI
// ABOUTME: Sets up global flags and subcommands

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Global flags.
var (
	cfgFile   string
	logLevel  string
	logFormat string
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hikma-av",
		Short: "HikmaAV - Stateless signature-based antivirus service",
		Long: `HikmaAV is a stateless, signature-based antivirus service that provides
fast hash lookups using a two-tier approach: Bloom filter for quick rejection
followed by BadgerDB for confirmed lookups.

Supports daemon mode with NATS messaging, direct CLI scans, and
feed management for ClamAV and abuse.ch signatures.`,
	}

	// Global flags.
	cmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: $HOME/.hikma-av/config.yaml)")
	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	cmd.PersistentFlags().StringVar(&logFormat, "log-format", "json", "log format (json, text)")

	// Add subcommands.
	cmd.AddCommand(newVersionCmd())
	cmd.AddCommand(newDaemonCmd())
	cmd.AddCommand(newScanCmd())
	cmd.AddCommand(newDBCmd())
	cmd.AddCommand(newFeedsCmd())
	cmd.AddCommand(newStatusCmd())

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("hikma-av version %s\n", version)
			fmt.Printf("  Git SHA:    %s\n", gitSHA)
			fmt.Printf("  Build Time: %s\n", buildTime)
		},
	}
}
