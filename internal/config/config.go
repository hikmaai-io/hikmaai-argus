// ABOUTME: Configuration loading and defaults for hikma-av
// ABOUTME: Handles YAML config files and environment variables

package config

import (
	"os"
	"path/filepath"
)

// Config holds the complete configuration for hikma-av.
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

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		DataDir: DefaultDataDir(),
		NATS: NATSConfig{
			URL:     "nats://localhost:4222",
			Subject: "hikma.av.scan",
			Queue:   "av-workers",
		},
		HTTP: HTTPConfig{
			Addr: ":8080",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
		Tracing: TracingConfig{
			Enabled:       false,
			Endpoint:      "localhost:4317",
			Insecure:      true,
			SamplingRatio: 1.0,
		},
		Feeds: FeedsConfig{
			UpdateInterval: "1h",
			Sources:        []string{"eicar"},
		},
	}
}

// DefaultDataDir returns the default data directory.
func DefaultDataDir() string {
	// Try XDG_DATA_HOME first.
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "hikma-av")
	}

	// Fall back to home directory.
	home, err := os.UserHomeDir()
	if err != nil {
		return "/var/lib/hikma-av"
	}

	return filepath.Join(home, ".local", "share", "hikma-av")
}

// DefaultConfigPath returns the default config file path.
func DefaultConfigPath() string {
	// Try XDG_CONFIG_HOME first.
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "hikma-av", "config.yaml")
	}

	// Fall back to home directory.
	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/hikma-av/config.yaml"
	}

	return filepath.Join(home, ".config", "hikma-av", "config.yaml")
}
