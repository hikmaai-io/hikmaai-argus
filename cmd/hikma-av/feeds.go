// ABOUTME: Feed management commands for signature updates
// ABOUTME: Provides list, update, and import operations

package main

import (
	"fmt"

	"github.com/spf13/cobra"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Configured feeds:")
			fmt.Println("  clamav   - ClamAV main.cvd and daily.cvd (not implemented)")
			fmt.Println("  abusech  - abuse.ch malware bazaar feed (not implemented)")
			fmt.Println("  eicar    - EICAR test signatures (built-in)")
			return nil
		},
	}
}

func newFeedsUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Trigger a manual feed update",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("feed update not yet implemented")
		},
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("feed import not yet implemented (file=%s, type=%s)", args[0], feedType)
		},
	}

	cmd.Flags().StringVarP(&feedType, "type", "t", "auto", "feed type (auto, clamav, csv)")
	cmd.Flags().StringVar(&dataDir, "data-dir", "", "data directory for BadgerDB")

	return cmd
}
