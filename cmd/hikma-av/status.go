// ABOUTME: Status command for checking daemon health
// ABOUTME: Shows daemon status, connection info, and statistics

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		Long:  `Check if the hikma-av daemon is running and show status information.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: Check NATS connection and daemon health endpoint.
			fmt.Println("hikma-av daemon status:")
			fmt.Println("  Daemon:  not connected (NATS check not implemented)")
			fmt.Println("  Mode:    CLI-only (direct database access)")
			fmt.Printf("  Version: %s\n", version)
			return nil
		},
	}
}
