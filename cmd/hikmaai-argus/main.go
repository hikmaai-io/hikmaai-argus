// ABOUTME: Main entry point for hikmaai-argus CLI
// ABOUTME: Initializes cobra root command and executes CLI

package main

import (
	"os"
)

// Version information (set by ldflags).
var (
	version   = "dev"
	gitSHA    = "unknown"
	buildTime = "unknown"
)

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
