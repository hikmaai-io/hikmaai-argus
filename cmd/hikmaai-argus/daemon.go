// ABOUTME: Daemon command for running hikmaai-argus as a service
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

	"github.com/hikmaai-io/hikmaai-argus/internal/api"
	"github.com/hikmaai-io/hikmaai-argus/internal/argus"
	"github.com/hikmaai-io/hikmaai-argus/internal/config"
	"github.com/hikmaai-io/hikmaai-argus/internal/dbupdater"
	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/feeds"
	"github.com/hikmaai-io/hikmaai-argus/internal/gcs"
	"github.com/hikmaai-io/hikmaai-argus/internal/observability"
	internalredis "github.com/hikmaai-io/hikmaai-argus/internal/redis"
	"github.com/hikmaai-io/hikmaai-argus/internal/scanner"
	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func newDaemonCmd() *cobra.Command {
	var (
		background         bool
		dataDir            string
		clamDBDir          string
		natsURL            string
		httpAddr           string
		trivyServerURL     string
		trivyCacheTTL       time.Duration
		trivyCacheDir       string
		trivySkipDBUpdate   bool
		// Argus worker flags.
		argusWorkerEnabled bool
		redisAddr          string
		redisPassword      string
		redisPrefix        string
		gcsBucket          string
		gcsDownloadDir     string
		// DB update service flags.
		dbUpdateEnabled         bool
		dbUpdateClamAVInterval  time.Duration
		dbUpdateTrivyInterval   time.Duration
		dbUpdateSignaturesInterval time.Duration
	)

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the antivirus daemon",
		Long: `Start the HikmaArgus daemon that listens for scan requests via NATS
and provides health/metrics endpoints via HTTP.

In foreground mode (default), the daemon runs in the current terminal.
Use --background to daemonize the process.

Use --db-update to enable periodic database updates for ClamAV, Trivy,
and signature feeds with retry logic and scan coordination.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if background {
				return fmt.Errorf("background mode not yet implemented")
			}
			return runDaemon(cmd.Context(), daemonConfig{
				DataDir:        dataDir,
				ClamDBDir:      clamDBDir,
				NatsURL:        natsURL,
				HTTPAddr:       httpAddr,
				LogLevel:       logLevel,
				LogFormat:      logFormat,
				TrivyServerURL: trivyServerURL,
				TrivyCacheTTL:       trivyCacheTTL,
				TrivyCacheDir:       trivyCacheDir,
				TrivySkipDBUpdate:   trivySkipDBUpdate,
				ArgusWorkerEnabled:  argusWorkerEnabled,
				RedisAddr:           redisAddr,
				RedisPassword:       redisPassword,
				RedisPrefix:         redisPrefix,
				GCSBucket:           gcsBucket,
				GCSDownloadDir:      gcsDownloadDir,
				// DB update service config.
				DBUpdateEnabled:            dbUpdateEnabled,
				DBUpdateClamAVInterval:     dbUpdateClamAVInterval,
				DBUpdateTrivyInterval:      dbUpdateTrivyInterval,
				DBUpdateSignaturesInterval: dbUpdateSignaturesInterval,
			})
		},
	}

	cmd.Flags().BoolVar(&background, "background", false, "run as a background daemon")
	cmd.Flags().StringVar(&dataDir, "data-dir", config.DefaultDataDir(), "data directory for HikmaAI signatures")
	cmd.Flags().StringVar(&clamDBDir, "clamdb-dir", config.DefaultClamDBDir(), "directory for ClamAV databases (CVD files)")
	cmd.Flags().StringVar(&natsURL, "nats-url", "nats://localhost:4222", "NATS server URL")
	cmd.Flags().StringVar(&httpAddr, "http-addr", ":8080", "HTTP address for health/metrics")
	cmd.Flags().StringVar(&trivyServerURL, "trivy-server", "", "Trivy server URL (e.g., http://trivy:4954)")
	cmd.Flags().DurationVar(&trivyCacheTTL, "trivy-cache-ttl", 1*time.Hour, "Trivy cache TTL")
	cmd.Flags().StringVar(&trivyCacheDir, "trivy-cache-dir", "/app/data/trivy-cache", "Trivy cache directory for vulnerability database")
	cmd.Flags().BoolVar(&trivySkipDBUpdate, "trivy-skip-db-update", false, "Skip Trivy database updates (use cached)")

	// Argus worker flags.
	cmd.Flags().BoolVar(&argusWorkerEnabled, "argus-worker", false, "enable Argus worker for Redis integration")
	cmd.Flags().StringVar(&redisAddr, "redis-addr", "localhost:6379", "Redis server address")
	cmd.Flags().StringVar(&redisPassword, "redis-password", "", "Redis password for authentication")
	cmd.Flags().StringVar(&redisPrefix, "redis-prefix", "argus:", "Redis key prefix")
	cmd.Flags().StringVar(&gcsBucket, "gcs-bucket", "", "GCS bucket for skill downloads")
	cmd.Flags().StringVar(&gcsDownloadDir, "gcs-download-dir", "/tmp/argus/downloads", "local directory for GCS downloads")

	// DB update service flags.
	cmd.Flags().BoolVar(&dbUpdateEnabled, "db-update", false, "enable background DB update service")
	cmd.Flags().DurationVar(&dbUpdateClamAVInterval, "db-update-clamav-interval", 1*time.Hour, "ClamAV database update interval")
	cmd.Flags().DurationVar(&dbUpdateTrivyInterval, "db-update-trivy-interval", 6*time.Hour, "Trivy database update interval")
	cmd.Flags().DurationVar(&dbUpdateSignaturesInterval, "db-update-signatures-interval", 1*time.Hour, "BadgerDB signature feed update interval")

	return cmd
}

type daemonConfig struct {
	DataDir        string
	ClamDBDir      string
	NatsURL        string
	HTTPAddr       string
	LogLevel       string
	LogFormat      string
	TrivyServerURL string
	TrivyCacheTTL       time.Duration
	TrivyCacheDir       string
	TrivySkipDBUpdate   bool
	// Argus worker settings.
	ArgusWorkerEnabled bool
	RedisAddr          string
	RedisPassword      string
	RedisPrefix        string
	GCSBucket          string
	GCSDownloadDir     string
	// DB update service settings.
	DBUpdateEnabled            bool
	DBUpdateClamAVInterval     time.Duration
	DBUpdateTrivyInterval      time.Duration
	DBUpdateSignaturesInterval time.Duration
}

func runDaemon(ctx context.Context, cfg daemonConfig) error {
	// Set up logging.
	logger := observability.NewLogger(observability.LoggingConfig{
		Level:       cfg.LogLevel,
		Format:      cfg.LogFormat,
		ServiceName: "hikmaai-argus",
		Version:     version,
	}, os.Stdout)

	slog.SetDefault(logger)
	logger.Info("starting hikmaai-argus daemon",
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
		DatabaseDir: cfg.ClamDBDir,
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

	// Create Trivy scanner if configured.
	var trivyScanner *trivy.Scanner
	var trivyCache *trivy.Cache
	trivyJobStore := api.NewTrivyJobStore()

	if cfg.TrivyServerURL != "" {
		var err error
		trivyCache, err = trivy.NewCache(trivy.CacheConfig{
			Path: filepath.Join(cfg.DataDir, "trivy-cache"),
			TTL:  cfg.TrivyCacheTTL,
		})
		if err != nil {
			logger.Warn("failed to create Trivy cache, continuing without caching",
				slog.String("error", err.Error()),
			)
		}

		trivyScanner = trivy.NewScanner(trivy.ScannerConfig{
			ServerURL: cfg.TrivyServerURL,
			Timeout:   2 * time.Minute,
			Cache:     trivyCache,
			Logger:    logger,
		})
		logger.Info("trivy scanner initialized",
			slog.String("server_url", cfg.TrivyServerURL),
		)
	}

	// Initialize DB update service if enabled (before API handler for health endpoint).
	var dbUpdateService *dbupdater.DBUpdateService
	var dbUpdateProvider api.DBUpdateStatusProvider
	if cfg.DBUpdateEnabled {
		dbUpdateService = initDBUpdateService(cfg, eng, logger)
		dbUpdateProvider = &dbUpdateStatusAdapter{service: dbUpdateService}
	}

	// Create API handler.
	handler := api.NewHandler(api.HandlerConfig{
		Engine:           eng,
		JobStore:         jobStore,
		ScanCache:        scanCache,
		Worker:           worker,
		UploadDir:        filepath.Join(cfg.DataDir, "uploads"),
		MaxFileSize:      100 * 1024 * 1024,
		TrivyScanner:     trivyScanner,
		TrivyJobStore:    trivyJobStore,
		DBUpdateProvider: dbUpdateProvider,
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

	// Start DB update service if enabled.
	if dbUpdateService != nil {
		if err := dbUpdateService.Start(workerCtx); err != nil {
			logger.Error("failed to start DB update service", slog.String("error", err.Error()))
		} else {
			logger.Info("db update service started",
				slog.Duration("clamav_interval", cfg.DBUpdateClamAVInterval),
				slog.Duration("trivy_interval", cfg.DBUpdateTrivyInterval),
				slog.Duration("signatures_interval", cfg.DBUpdateSignaturesInterval),
			)
		}
	}

	// Start Argus worker if enabled.
	var argusWorker *argus.Worker
	if cfg.ArgusWorkerEnabled {
		var err error
		argusWorker, err = initArgusWorker(workerCtx, cfg, clamScanner, logger)
		if err != nil {
			logger.Error("failed to initialize Argus worker", slog.String("error", err.Error()))
		} else {
			if err := argusWorker.Start(workerCtx); err != nil {
				logger.Error("failed to start Argus worker", slog.String("error", err.Error()))
			}
		}
	}

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

	if dbUpdateService != nil {
		dbUpdateService.Stop()
	}

	if argusWorker != nil {
		argusWorker.Stop()
	}

	if trivyCache != nil {
		trivyCache.Close()
	}

	logger.Info("daemon stopped")

	return nil
}

// initArgusWorker initializes the Argus worker for Redis integration.
func initArgusWorker(ctx context.Context, cfg daemonConfig, clamScanner *scanner.ClamAVScanner, logger *slog.Logger) (*argus.Worker, error) {
	logger.Info("initializing Argus worker",
		slog.String("redis_addr", cfg.RedisAddr),
		slog.String("redis_prefix", cfg.RedisPrefix),
		slog.String("gcs_bucket", cfg.GCSBucket),
	)

	// Create Redis client.
	redisClient, err := internalredis.NewClient(internalredis.Config{
		Addr:         cfg.RedisAddr,
		Password:     cfg.RedisPassword,
		Prefix:       cfg.RedisPrefix,
		PoolSize:     10,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("creating redis client: %w", err)
	}

	// Create GCS client.
	var gcsClient *gcs.Client
	if cfg.GCSBucket != "" {
		gcsClient, err = gcs.NewClient(ctx, gcs.Config{
			Bucket:      cfg.GCSBucket,
			DownloadDir: cfg.GCSDownloadDir,
		})
		if err != nil {
			_ = redisClient.Close()
			return nil, fmt.Errorf("creating gcs client: %w", err)
		}
	}

	// Create Trivy scanner for Argus (local mode).
	// CacheDir persists the vulnerability DB across container restarts.
	// SkipDBUpdate can be enabled for air-gapped environments with pre-warmed cache.
	trivyScanner := trivy.NewUnifiedScanner(&config.TrivyConfig{
		Mode:         "local",
		Binary:       "trivy",
		Timeout:      5 * time.Minute,
		CacheDir:     cfg.TrivyCacheDir,
		SkipDBUpdate: cfg.TrivySkipDBUpdate,
	})

	// Create scanner runner.
	runner := argus.NewRunner(argus.RunnerConfig{
		TrivyScanner:  trivyScanner,
		ClamAVScanner: &clamAVScannerAdapter{scanner: clamScanner},
	})

	// Get hostname for consumer name.
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "argus-worker"
	}

	// Create worker.
	worker, err := argus.NewWorker(
		argus.WorkerConfig{
			TaskQueue:         "argus_task_queue",
			ConsumerGroup:     "argus-workers",
			ConsumerName:      hostname,
			CompletionPrefix:  "argus_completion",
			Workers:           2,
			DefaultTimeout:    15 * time.Minute,
			MaxRetries:        3,
			CleanupOnComplete: true,
			StateTTL:          7 * 24 * time.Hour,
		},
		redisClient,
		gcsClient,
		runner,
		logger,
	)
	if err != nil {
		_ = redisClient.Close()
		if gcsClient != nil {
			_ = gcsClient.Close()
		}
		return nil, fmt.Errorf("creating argus worker: %w", err)
	}

	return worker, nil
}

// clamAVScannerAdapter adapts ClamAVScanner to the argus.ClamAVScanner interface.
type clamAVScannerAdapter struct {
	scanner *scanner.ClamAVScanner
}

func (a *clamAVScannerAdapter) ScanFile(ctx context.Context, path string) (*types.ScanResult, error) {
	return a.scanner.ScanFile(ctx, path)
}

func (a *clamAVScannerAdapter) ScanDirectory(ctx context.Context, path string) ([]*types.ScanResult, error) {
	return a.scanner.ScanDir(ctx, path, true)
}

// initDBUpdateService initializes the database update service.
func initDBUpdateService(cfg daemonConfig, eng *engine.Engine, logger *slog.Logger) *dbupdater.DBUpdateService {
	// Create the DB update service.
	service := dbupdater.NewDBUpdateService(dbupdater.DBUpdateServiceConfig{
		Logger: logger,
	})

	// Register ClamAV updater.
	clamUpdater := dbupdater.NewClamAVUpdater(dbupdater.ClamAVUpdaterConfig{
		DatabaseDir: cfg.ClamDBDir,
	})
	service.RegisterUpdater(clamUpdater, cfg.DBUpdateClamAVInterval)

	// Register Trivy updater.
	trivyUpdater := dbupdater.NewTrivyUpdater(dbupdater.TrivyUpdaterConfig{
		Binary:   "trivy",
		CacheDir: cfg.TrivyCacheDir,
	})
	service.RegisterUpdater(trivyUpdater, cfg.DBUpdateTrivyInterval)

	// Register signature feed updater for BadgerDB.
	sigUpdater := dbupdater.NewSignatureFeedUpdater(dbupdater.SignatureFeedUpdaterConfig{
		Engine: &signatureEngineAdapter{engine: eng},
	})

	// Register signature feeds.
	sigUpdater.RegisterFeed(&signatureFeedAdapter{feed: feeds.NewMalwareBazaarFeed()})
	sigUpdater.RegisterFeed(&signatureFeedAdapter{feed: feeds.NewThreatFoxFeed()})

	service.RegisterUpdater(sigUpdater, cfg.DBUpdateSignaturesInterval)

	return service
}

// signatureEngineAdapter adapts engine.Engine to dbupdater.SignatureEngine.
type signatureEngineAdapter struct {
	engine *engine.Engine
}

func (a *signatureEngineAdapter) BatchAddSignatures(ctx context.Context, sigs []*types.Signature) error {
	return a.engine.BatchAddSignatures(ctx, sigs)
}

func (a *signatureEngineAdapter) Count() int64 {
	stats, err := a.engine.Stats(context.Background())
	if err != nil {
		return 0
	}
	return stats.SignatureCount
}

// signatureFeedAdapter adapts existing feeds to dbupdater.SignatureFeed interface.
type signatureFeedAdapter struct {
	feed interface {
		Name() string
		Fetch(ctx context.Context) ([]*types.Signature, error)
	}
}

func (a *signatureFeedAdapter) Name() string {
	return a.feed.Name()
}

func (a *signatureFeedAdapter) Fetch(ctx context.Context) ([]*types.Signature, error) {
	return a.feed.Fetch(ctx)
}

// dbUpdateStatusAdapter adapts dbupdater.DBUpdateService to api.DBUpdateStatusProvider.
type dbUpdateStatusAdapter struct {
	service *dbupdater.DBUpdateService
}

func (a *dbUpdateStatusAdapter) GetStatus() map[string]*api.DBUpdateStatus {
	statuses := a.service.GetStatus()
	result := make(map[string]*api.DBUpdateStatus, len(statuses))

	for name, s := range statuses {
		status := &api.DBUpdateStatus{
			Name:    s.Name,
			Status:  string(s.Status),
			Ready:   s.Ready,
			Version: s.Version.Version,
		}
		if !s.LastUpdate.IsZero() {
			t := s.LastUpdate
			status.LastUpdate = &t
		}
		if !s.NextScheduled.IsZero() {
			t := s.NextScheduled
			status.NextScheduled = &t
		}
		if s.LastError != "" {
			status.LastError = s.LastError
		}
		result[name] = status
	}
	return result
}
