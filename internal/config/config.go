// ABOUTME: Configuration loading and defaults for hikmaai-argus
// ABOUTME: Handles YAML config files and environment variables

package config

import (
	"os"
	"path/filepath"
	"time"

	internalredis "github.com/hikmaai-io/hikmaai-argus/internal/redis"
)

// ToRedisConfig converts RedisConfig to the internal redis.Config type.
func (c *RedisConfig) ToRedisConfig() internalredis.Config {
	return internalredis.Config{
		Addr:         c.Addr,
		Password:     c.Password,
		DB:           c.DB,
		Prefix:       c.Prefix,
		PoolSize:     c.PoolSize,
		ReadTimeout:  c.ReadTimeout,
		WriteTimeout: c.WriteTimeout,
	}
}

// Config holds the complete configuration for hikmaai-argus.
type Config struct {
	// Data directory for BadgerDB and bloom filter.
	DataDir string `yaml:"data_dir"`

	// NATS configuration.
	NATS NATSConfig `yaml:"nats"`

	// HTTP server configuration.
	HTTP HTTPConfig `yaml:"http"`

	// Logging configuration.
	Log LogConfig `yaml:"log"`

	// Tracing configuration.
	Tracing TracingConfig `yaml:"tracing"`

	// Feed configuration.
	Feeds FeedsConfig `yaml:"feeds"`

	// ClamAV scanner configuration.
	ClamAV ClamAVConfig `yaml:"clamav"`

	// Trivy dependency scanner configuration.
	Trivy TrivyConfig `yaml:"trivy"`

	// Redis configuration for Redis integration.
	Redis RedisConfig `yaml:"redis"`

	// GCS configuration for skill artifact storage.
	GCS GCSConfig `yaml:"gcs"`

	// ArgusWorker configuration for processing Redis tasks.
	ArgusWorker ArgusWorkerConfig `yaml:"argus_worker"`

	// DBUpdate configures the database update service.
	DBUpdate DBUpdateConfig `yaml:"db_update"`
}

// NATSConfig holds NATS connection settings.
type NATSConfig struct {
	URL     string `yaml:"url"`
	Subject string `yaml:"subject"`
	Queue   string `yaml:"queue"`
}

// HTTPConfig holds HTTP server settings.
type HTTPConfig struct {
	Addr string `yaml:"addr"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// TracingConfig holds tracing settings.
type TracingConfig struct {
	Enabled       bool    `yaml:"enabled"`
	Endpoint      string  `yaml:"endpoint"`
	Insecure      bool    `yaml:"insecure"`
	SamplingRatio float64 `yaml:"sampling_ratio"`
}

// FeedsConfig holds feed settings.
type FeedsConfig struct {
	UpdateInterval string   `yaml:"update_interval"`
	Sources        []string `yaml:"sources"`
}

// ClamAVConfig holds ClamAV scanner settings.
type ClamAVConfig struct {
	// Enabled controls whether ClamAV scanning is available.
	Enabled bool `yaml:"enabled"`

	// Mode selects the scanner mode: "clamscan" (default) or "clamd".
	// clamscan: Uses the clamscan binary directly (slower, no daemon needed).
	// clamd: Connects to a running clamd daemon (faster, requires daemon).
	Mode string `yaml:"mode"`

	// Binary is the path to the clamscan binary (only for clamscan mode).
	Binary string `yaml:"binary"`

	// DatabaseDir is the path to the ClamAV database directory.
	// CVD files (main.cvd, daily.cvd, bytecode.cvd) are stored here.
	DatabaseDir string `yaml:"database_dir"`

	// Address is the clamd address (only for clamd mode).
	// Format: "unix:///path/to/clamd.sock" or "tcp://host:port".
	Address string `yaml:"address"`

	// Timeout for scan operations.
	Timeout time.Duration `yaml:"timeout"`

	// MaxFileSize is the maximum file size to scan (bytes).
	MaxFileSize int64 `yaml:"max_file_size"`

	// Workers is the number of concurrent scan workers.
	Workers int `yaml:"workers"`

	// CacheTTL is the time-to-live for cached scan results.
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// RedisConfig holds Redis connection settings for Redis integration.
type RedisConfig struct {
	// Enabled controls whether Redis integration is active.
	Enabled bool `yaml:"enabled"`

	// Addr is the Redis server address (host:port).
	Addr string `yaml:"addr"`

	// Password for Redis authentication (optional).
	Password string `yaml:"password"`

	// DB is the Redis database number.
	DB int `yaml:"db"`

	// Prefix is prepended to all keys for multi-tenant isolation.
	// Example: "argus:" results in keys like "argus:job_state:123".
	Prefix string `yaml:"prefix"`

	// PoolSize is the number of connections in the pool.
	PoolSize int `yaml:"pool_size"`

	// ReadTimeout for Redis operations.
	ReadTimeout time.Duration `yaml:"read_timeout"`

	// WriteTimeout for Redis operations.
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// GCSConfig holds GCS client settings for skill artifact storage.
type GCSConfig struct {
	// Enabled controls whether GCS integration is active.
	Enabled bool `yaml:"enabled"`

	// Bucket is the GCS bucket name.
	Bucket string `yaml:"bucket"`

	// ProjectID is the GCP project ID (optional for ADC).
	ProjectID string `yaml:"project_id"`

	// CredentialsFile is the path to service account JSON (optional).
	// If empty, uses Application Default Credentials (ADC).
	CredentialsFile string `yaml:"credentials_file"`

	// DownloadDir is the local directory for downloaded files.
	DownloadDir string `yaml:"download_dir"`
}

// ArgusWorkerConfig holds Argus worker settings for Redis integration.
type ArgusWorkerConfig struct {
	// Enabled controls whether Argus worker is active.
	Enabled bool `yaml:"enabled"`

	// TaskQueue is the Redis stream name for incoming tasks.
	TaskQueue string `yaml:"task_queue"`

	// ConsumerGroup is the consumer group name for scaling.
	ConsumerGroup string `yaml:"consumer_group"`

	// ConsumerName is this instance's consumer name.
	ConsumerName string `yaml:"consumer_name"`

	// CompletionPrefix is the prefix for completion signal streams.
	CompletionPrefix string `yaml:"completion_prefix"`

	// CancelPrefix is the prefix for cancellation Pub/Sub channels.
	// Cancellation signals are published to: {cancel_prefix}:{job_id}
	CancelPrefix string `yaml:"cancel_prefix"`

	// Workers is the number of concurrent scan workers.
	Workers int `yaml:"workers"`

	// DefaultTimeout for scan operations.
	DefaultTimeout time.Duration `yaml:"default_timeout"`

	// MaxRetries before giving up on a task.
	MaxRetries int `yaml:"max_retries"`

	// CleanupOnComplete removes temp files after scan.
	CleanupOnComplete bool `yaml:"cleanup_on_complete"`

	// StateTTL is the TTL for job state entries (default: 7 days).
	StateTTL time.Duration `yaml:"state_ttl"`
}

// TrivyConfig holds Trivy dependency scanner settings.
type TrivyConfig struct {
	// Enabled controls whether Trivy scanning is available.
	Enabled bool `yaml:"enabled"`

	// Mode selects the scanner mode: "local" (default) or "server".
	// local: Uses the trivy binary directly (requires local trivy installation).
	// server: Connects to a remote Trivy server via Twirp (requires ServerURL).
	Mode string `yaml:"mode"`

	// Binary is the path to the trivy binary (only for local mode).
	Binary string `yaml:"binary"`

	// ServerURL is the Trivy server Twirp endpoint (only for server mode).
	// Example: "http://trivy-server:4954"
	ServerURL string `yaml:"server_url"`

	// CacheDir is the local cache directory for trivy databases (local mode only).
	CacheDir string `yaml:"cache_dir"`

	// SkipDBUpdate skips updating the vulnerability database (local mode only).
	SkipDBUpdate bool `yaml:"skip_db_update"`

	// Timeout for scan operations.
	Timeout time.Duration `yaml:"timeout"`

	// DefaultSeverities to filter (if not specified in request).
	DefaultSeverities []string `yaml:"default_severities"`

	// SupportedEcosystems lists package ecosystems to scan.
	SupportedEcosystems []string `yaml:"supported_ecosystems"`

	// Workers is the number of concurrent scan workers.
	Workers int `yaml:"workers"`

	// CacheTTL is the time-to-live for cached scan results.
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// DefaultConfig returns a Config with default values.
// All external dependencies (NATS, tracing) are disabled by default
// for standalone single-binary operation.
func DefaultConfig() *Config {
	return &Config{
		DataDir: DefaultDataDir(),
		NATS: NATSConfig{
			// Disabled by default; set URL to enable
			URL:     "",
			Subject: "hikmaai.argus.scan",
			Queue:   "argus-workers",
		},
		HTTP: HTTPConfig{
			// Disabled by default; set Addr to enable (e.g., ":8080")
			Addr: "",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "text", // Human-readable by default
		},
		Tracing: TracingConfig{
			Enabled:       false, // Disabled by default
			Endpoint:      "localhost:4317",
			Insecure:      true,
			SamplingRatio: 1.0,
		},
		Feeds: FeedsConfig{
			UpdateInterval: "1h",
			Sources:        []string{"eicar"},
		},
		ClamAV: ClamAVConfig{
			Enabled:     false, // Disabled by default
			Mode:        "clamscan",
			Binary:      "clamscan",
			DatabaseDir: "", // Set dynamically to DataDir/clamav
			Address:     "unix:///var/run/clamav/clamd.ctl",
			Timeout:     5 * time.Minute,
			MaxFileSize: 100 * 1024 * 1024, // 100MB
			Workers:     2,
			CacheTTL:    24 * time.Hour,
		},
		Trivy: TrivyConfig{
			Enabled:             false,   // Disabled by default
			Mode:                "local", // Use local trivy binary by default
			Binary:              "trivy",
			ServerURL:           "", // Set for server mode
			CacheDir:            "", // Uses trivy default
			SkipDBUpdate:        false,
			Timeout:             5 * time.Minute,
			DefaultSeverities:   []string{"HIGH", "CRITICAL"},
			SupportedEcosystems: []string{"pip", "npm", "gomod", "cargo", "composer"},
			Workers:             2,
			CacheTTL:            1 * time.Hour,
		},
		Redis: RedisConfig{
			Enabled:      false, // Disabled by default
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0,
			Prefix:       "argus:",
			PoolSize:     10,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		GCS: GCSConfig{
			Enabled:         false, // Disabled by default
			Bucket:          "",
			ProjectID:       "",
			CredentialsFile: "",
			DownloadDir:     "/tmp/argus/downloads",
		},
		ArgusWorker: ArgusWorkerConfig{
			Enabled:           false, // Disabled by default
			TaskQueue:         "argus_task_queue",
			ConsumerGroup:     "argus-workers",
			ConsumerName:      "", // Auto-generated from hostname
			CompletionPrefix:  "argus_completion",
			CancelPrefix:      "argus_cancel",
			Workers:           2,
			DefaultTimeout:    15 * time.Minute,
			MaxRetries:        3,
			CleanupOnComplete: true,
			StateTTL:          7 * 24 * time.Hour, // 7 days
		},
		DBUpdate: DefaultDBUpdateConfig(),
	}
}

// DefaultDataDir returns the default data directory for HikmaAI signatures.
func DefaultDataDir() string {
	return "data/hikmaaidb"
}

// DefaultClamDBDir returns the default directory for ClamAV databases.
func DefaultClamDBDir() string {
	return "data/clamdb"
}

// DefaultConfigPath returns the default config file path.
func DefaultConfigPath() string {
	// Try XDG_CONFIG_HOME first.
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "hikmaai-argus", "config.yaml")
	}

	// Fall back to home directory.
	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/hikmaai-argus/config.yaml"
	}

	return filepath.Join(home, ".config", "hikmaai-argus", "config.yaml")
}

// GetClamAVDatabaseDir returns the ClamAV database directory.
// If ClamAV.DatabaseDir is set, it uses that; otherwise defaults to DefaultClamDBDir().
func (c *Config) GetClamAVDatabaseDir() string {
	if c.ClamAV.DatabaseDir != "" {
		return c.ClamAV.DatabaseDir
	}
	return DefaultClamDBDir()
}
