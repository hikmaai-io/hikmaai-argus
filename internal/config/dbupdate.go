// ABOUTME: DB update configuration types for the DBUpdateService
// ABOUTME: Configures intervals, retry settings, and source-specific options

package config

import "time"

// DBUpdateConfig configures the database update service.
type DBUpdateConfig struct {
	// Enabled controls whether the DB update service is active.
	Enabled bool `yaml:"enabled"`

	// ClamAV configures ClamAV database updates.
	ClamAV DBUpdateSourceConfig `yaml:"clamav"`

	// Trivy configures Trivy database updates.
	Trivy DBUpdateSourceConfig `yaml:"trivy"`

	// Signatures configures BadgerDB signature feed updates.
	Signatures DBUpdateSourceConfig `yaml:"signatures"`
}

// DBUpdateSourceConfig configures a specific update source.
type DBUpdateSourceConfig struct {
	// Enabled controls whether this source is updated.
	Enabled bool `yaml:"enabled"`

	// Interval is how often to check for updates.
	Interval time.Duration `yaml:"interval"`

	// Retry configures retry behavior for failed updates.
	// If nil, uses DefaultRetryConfig().
	Retry *RetryConfig `yaml:"retry,omitempty"`
}

// GetRetry returns the retry configuration, using defaults if not set.
func (c *DBUpdateSourceConfig) GetRetry() RetryConfig {
	if c.Retry != nil {
		return *c.Retry
	}
	return DefaultRetryConfig()
}

// RetryConfig configures retry behavior with exponential backoff.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts.
	MaxRetries int `yaml:"max_retries"`

	// InitialDelay is the delay before the first retry.
	InitialDelay time.Duration `yaml:"initial_delay"`

	// MaxDelay is the maximum delay between retries.
	MaxDelay time.Duration `yaml:"max_delay"`

	// Multiplier is the exponential backoff multiplier.
	Multiplier float64 `yaml:"multiplier"`

	// JitterFraction is the fraction of delay to randomize (0-1).
	JitterFraction float64 `yaml:"jitter_fraction"`
}

// DefaultDBUpdateConfig returns a DBUpdateConfig with sensible defaults.
func DefaultDBUpdateConfig() DBUpdateConfig {
	return DBUpdateConfig{
		Enabled:    false, // Disabled by default.
		ClamAV:     DefaultDBUpdateSourceConfig(),
		Trivy:      DBUpdateSourceConfig{Enabled: true, Interval: 6 * time.Hour},
		Signatures: DefaultDBUpdateSourceConfig(),
	}
}

// DefaultDBUpdateSourceConfig returns default source configuration.
func DefaultDBUpdateSourceConfig() DBUpdateSourceConfig {
	return DBUpdateSourceConfig{
		Enabled:  true,
		Interval: 1 * time.Hour,
		Retry:    nil, // Uses DefaultRetryConfig via GetRetry().
	}
}

// DefaultRetryConfig returns default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     5,
		InitialDelay:   30 * time.Second,
		MaxDelay:       30 * time.Minute,
		Multiplier:     2.0,
		JitterFraction: 0.2,
	}
}
