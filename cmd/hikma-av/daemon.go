// ABOUTME: Daemon command for running hikma-av as a service
// ABOUTME: Supports foreground and background modes with NATS messaging and HTTP API

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hikmaai-io/hikma-av/internal/api"
	"github.com/hikmaai-io/hikma-av/internal/config"
	"github.com/hikmaai-io/hikma-av/internal/engine"
	"github.com/hikmaai-io/hikma-av/internal/observability"
	"github.com/hikmaai-io/hikma-av/internal/scanner"
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

	// Create job store.
	jobStore, err := engine.NewJobStore(engine.StoreConfig{
		Path: filepath.Join(cfg.DataDir, "jobs"),
	})
	if err != nil {
		return fmt.Errorf("creating job store: %w", err)
	}
	defer jobStore.Close()
	logger.Info("job store initialized")

	// Create scan cache.
	scanCache, err := engine.NewScanCache(
		engine.StoreConfig{Path: filepath.Join(cfg.DataDir, "cache")},
		24*time.Hour,
	)
	if err != nil {
		return fmt.Errorf("creating scan cache: %w", err)
	}
	defer scanCache.Close()
	logger.Info("scan cache initialized")

	// Create ClamAV scanner.
	clamScanner := scanner.NewClamAVScanner(&config.ClamAVConfig{
		Mode:        "clamscan",
		Binary:      "clamscan",
		DatabaseDir: filepath.Join(cfg.DataDir, "clamav"),
		Timeout:     5 * time.Minute,
	})

	// Create scan worker.
	worker := scanner.NewWorker(scanner.WorkerConfig{
		Scanner:         clamScanner,
		JobStore:        jobStore,
		ScanCache:       scanCache,
		SignatureEngine: eng,
		Concurrency:     2,
	})

	// Start worker.
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()
	worker.Start(workerCtx)
	logger.Info("scan worker started", slog.Int("workers", 2))

	// Create API handler.
	handler := api.NewHandler(api.HandlerConfig{
		Engine:      eng,
		JobStore:    jobStore,
		ScanCache:   scanCache,
		Worker:      worker,
		UploadDir:   filepath.Join(cfg.DataDir, "uploads"),
		MaxFileSize: 100 * 1024 * 1024,
	})

	// Start HTTP server.
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	httpServer := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: api.LoggingMiddleware(mux),
	}

	go func() {
		logger.Info("starting HTTP server", slog.String("addr", cfg.HTTPAddr))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", slog.String("error", err.Error()))
		}
	}()

	// TODO: Connect to NATS and start message handler.

	// Wait for shutdown signal.
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("daemon ready, waiting for requests")
	<-ctx.Done()

	logger.Info("shutting down daemon")

	// Graceful shutdown.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("HTTP server shutdown error", slog.String("error", err.Error()))
	}

	worker.Stop()
	logger.Info("daemon stopped")

	return nil
}
