// ABOUTME: Exponential backoff with jitter for retry logic
// ABOUTME: Configurable delays, max retries, and multiplicative growth

package dbupdater

import (
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

// Default backoff configuration values.
const (
	DefaultMaxRetries     = 5
	DefaultInitialDelay   = 30 * time.Second
	DefaultMaxDelay       = 30 * time.Minute
	DefaultMultiplier     = 2.0
	DefaultJitterFraction = 0.2 // 20% jitter.
)

// BackoffConfig configures exponential backoff behavior.
type BackoffConfig struct {
	// MaxRetries is the maximum number of retry attempts.
	// Zero uses DefaultMaxRetries.
	MaxRetries int

	// InitialDelay is the delay after the first failure.
	// Zero uses DefaultInitialDelay.
	InitialDelay time.Duration

	// MaxDelay caps the maximum delay between retries.
	// Zero uses DefaultMaxDelay.
	MaxDelay time.Duration

	// Multiplier is the factor to multiply delay on each retry.
	// Must be >= 1.0. Zero uses DefaultMultiplier.
	Multiplier float64

	// JitterFraction adds randomness to delays.
	// 0.2 means ±20% variation. Must be in [0, 1].
	// Zero disables jitter.
	JitterFraction float64
}

// Validate checks if the configuration is valid.
func (c *BackoffConfig) Validate() error {
	if c.JitterFraction < 0 || c.JitterFraction > 1 {
		return errors.New("jitter fraction must be between 0 and 1")
	}
	if c.Multiplier != 0 && c.Multiplier < 1 {
		return errors.New("multiplier must be at least 1")
	}
	return nil
}

// applyDefaults fills in zero values with defaults.
func (c *BackoffConfig) applyDefaults() {
	if c.MaxRetries == 0 {
		c.MaxRetries = DefaultMaxRetries
	}
	if c.InitialDelay == 0 {
		c.InitialDelay = DefaultInitialDelay
	}
	if c.MaxDelay == 0 {
		c.MaxDelay = DefaultMaxDelay
	}
	if c.Multiplier == 0 {
		c.Multiplier = DefaultMultiplier
	}
	// Note: JitterFraction of 0 disables jitter (explicit choice).
	// Use DefaultBackoffConfig() for defaults with jitter enabled.
}

// DefaultBackoffConfig returns a BackoffConfig with all defaults applied.
func DefaultBackoffConfig() BackoffConfig {
	return BackoffConfig{
		MaxRetries:     DefaultMaxRetries,
		InitialDelay:   DefaultInitialDelay,
		MaxDelay:       DefaultMaxDelay,
		Multiplier:     DefaultMultiplier,
		JitterFraction: DefaultJitterFraction,
	}
}

// Backoff implements exponential backoff with optional jitter.
type Backoff struct {
	mu           sync.Mutex
	config       BackoffConfig
	attempts     int
	currentDelay time.Duration
}

// NewBackoff creates a new Backoff with the given configuration.
// Zero values in config use defaults.
func NewBackoff(config BackoffConfig) *Backoff {
	config.applyDefaults()
	return &Backoff{
		config:       config,
		currentDelay: config.InitialDelay,
	}
}

// NextDelay returns the next delay duration and whether more retries are available.
// Returns (0, false) if max retries exceeded.
func (b *Backoff) NextDelay() (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.attempts >= b.config.MaxRetries {
		return 0, false
	}

	// Calculate delay for this attempt.
	delay := b.currentDelay

	// Apply jitter if configured.
	if b.config.JitterFraction > 0 {
		delay = b.applyJitter(delay)
	}

	// Increment attempts and prepare next delay.
	b.attempts++
	nextDelay := time.Duration(float64(b.currentDelay) * b.config.Multiplier)
	if nextDelay > b.config.MaxDelay {
		nextDelay = b.config.MaxDelay
	}
	b.currentDelay = nextDelay

	return delay, true
}

// applyJitter adds random variation to the delay.
func (b *Backoff) applyJitter(delay time.Duration) time.Duration {
	// Jitter: delay * (1 - fraction) to delay * (1 + fraction).
	jitterRange := float64(delay) * b.config.JitterFraction
	jitter := (rand.Float64()*2 - 1) * jitterRange
	return time.Duration(float64(delay) + jitter)
}

// Reset resets the backoff to its initial state.
func (b *Backoff) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.attempts = 0
	b.currentDelay = b.config.InitialDelay
}

// Attempts returns the number of attempts made so far.
func (b *Backoff) Attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempts
}
