// ABOUTME: Daemon command for running hikma-av as a service
// ABOUTME: Supports foreground and background modes with NATS messaging

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikma-av/internal/config"
	"github.com/hikmaai-io/hikma-av/internal/engine"
	"github.com/hikmaai-io/hikma-av/internal/observability"
)

func newDaemonCmd() *cobra.Command {
	var (
		background bool
		dataDir    string
		natsURL    string
		httpAddr   string
	)

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the antivirus daemon",
		Long: `Start the HikmaAV daemon that listens for scan requests via NATS
and provides health/metrics endpoints via HTTP.

In foreground mode (default), the daemon runs in the current terminal.
Use --background to daemonize the process.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if background {
				return fmt.Errorf("background mode not yet implemented")
			}
			return runDaemon(cmd.Context(), daemonConfig{
				DataDir:   dataDir,
				NatsURL:   natsURL,
				HTTPAddr:  httpAddr,
				LogLevel:  logLevel,
				LogFormat: logFormat,
			})
		},
	}

	cmd.Flags().BoolVar(&background, "background", false, "run as a background daemon")
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for BadgerDB")
	cmd.Flags().StringVar(&natsURL, "nats-url", "nats://localhost:4222", "NATS server URL")
	cmd.Flags().StringVar(&httpAddr, "http-addr", ":8080", "HTTP address for health/metrics")

	return cmd
}

type daemonConfig struct {
	DataDir   string
	NatsURL   string
	HTTPAddr  string
	LogLevel  string
	LogFormat string
}

func runDaemon(ctx context.Context, cfg daemonConfig) error {
	// Set up logging.
	logger := observability.NewLogger(observability.LoggingConfig{
		Level:       cfg.LogLevel,
		Format:      cfg.LogFormat,
		ServiceName: "hikma-av",
		Version:     version,
	}, os.Stdout)

	slog.SetDefault(logger)
	logger.Info("starting hikma-av daemon",
		slog.String("version", version),
		slog.String("data_dir", cfg.DataDir),
		slog.String("nats_url", cfg.NatsURL),
		slog.String("http_addr", cfg.HTTPAddr),
	)

	// Ensure data directory exists.
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Create engine.
	eng, err := engine.NewEngine(engine.EngineConfig{
		StoreConfig: engine.StoreConfig{
			Path: cfg.DataDir,
		},
		BloomConfig: engine.BloomConfig{
			ExpectedItems:     10_000_000, // 10M signatures.
			FalsePositiveRate: 0.001,      // 0.1% false positive rate.
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}
	defer eng.Close()

	logger.Info("engine initialized")

	// TODO: Connect to NATS and start message handler.
	// TODO: Start HTTP server for health/metrics.

	// Wait for shutdown signal.
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("daemon ready, waiting for requests")
	<-ctx.Done()

	logger.Info("shutting down daemon")
	return nil
}
