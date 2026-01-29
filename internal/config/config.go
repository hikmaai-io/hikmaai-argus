// ABOUTME: Configuration loading and defaults for hikmaai-argus
// ABOUTME: Handles YAML config files and environment variables

package config

import (
	"os"
	"path/filepath"
	"time"
)

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
			ServerURL:           "",      // Set for server mode
			CacheDir:            "",      // Uses trivy default
			SkipDBUpdate:        false,
			Timeout:             5 * time.Minute,
			DefaultSeverities:   []string{"HIGH", "CRITICAL"},
			SupportedEcosystems: []string{"pip", "npm", "gomod", "cargo", "composer"},
			Workers:             2,
			CacheTTL:            1 * time.Hour,
		},
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
