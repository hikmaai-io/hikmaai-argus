// ABOUTME: Tests for exponential backoff with jitter for retry logic
// ABOUTME: Validates delay calculation, reset, and configurable parameters

package dbupdater

import (
	"testing"
	"time"
)

func TestBackoff_DefaultValues(t *testing.T) {
	t.Parallel()

	b := NewBackoff(BackoffConfig{})

	// Verify defaults are applied for non-zero fields.
	if b.config.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", b.config.MaxRetries, DefaultMaxRetries)
	}
	if b.config.InitialDelay != DefaultInitialDelay {
		t.Errorf("InitialDelay = %v, want %v", b.config.InitialDelay, DefaultInitialDelay)
	}
	if b.config.MaxDelay != DefaultMaxDelay {
		t.Errorf("MaxDelay = %v, want %v", b.config.MaxDelay, DefaultMaxDelay)
	}
	if b.config.Multiplier != DefaultMultiplier {
		t.Errorf("Multiplier = %v, want %v", b.config.Multiplier, DefaultMultiplier)
	}
	// JitterFraction of 0 is valid (disables jitter); use DefaultBackoffConfig() for full defaults.
}

func TestDefaultBackoffConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultBackoffConfig()

	if cfg.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", cfg.MaxRetries, DefaultMaxRetries)
	}
	if cfg.InitialDelay != DefaultInitialDelay {
		t.Errorf("InitialDelay = %v, want %v", cfg.InitialDelay, DefaultInitialDelay)
	}
	if cfg.MaxDelay != DefaultMaxDelay {
		t.Errorf("MaxDelay = %v, want %v", cfg.MaxDelay, DefaultMaxDelay)
	}
	if cfg.Multiplier != DefaultMultiplier {
		t.Errorf("Multiplier = %v, want %v", cfg.Multiplier, DefaultMultiplier)
	}
	if cfg.JitterFraction != DefaultJitterFraction {
		t.Errorf("JitterFraction = %v, want %v", cfg.JitterFraction, DefaultJitterFraction)
	}
}

func TestBackoff_NextDelay_FirstCall(t *testing.T) {
	t.Parallel()

	b := NewBackoff(BackoffConfig{
		InitialDelay:   30 * time.Second,
		JitterFraction: 0, // Disable jitter for deterministic test.
	})

	delay, ok := b.NextDelay()

	if !ok {
		t.Error("NextDelay() should return ok=true on first call")
	}
	if delay != 30*time.Second {
		t.Errorf("NextDelay() = %v, want %v", delay, 30*time.Second)
	}
}

func TestBackoff_NextDelay_ExponentialIncrease(t *testing.T) {
	t.Parallel()

	b := NewBackoff(BackoffConfig{
		MaxRetries:     10,
		InitialDelay:   1 * time.Second,
		MaxDelay:       1 * time.Hour, // High enough to not cap.
		Multiplier:     2.0,
		JitterFraction: 0, // Disable jitter.
	})

	expectedDelays := []time.Duration{
		1 * time.Second,  // 1st call.
		2 * time.Second,  // 2nd call: 1 * 2.
		4 * time.Second,  // 3rd call: 2 * 2.
		8 * time.Second,  // 4th call: 4 * 2.
		16 * time.Second, // 5th call: 8 * 2.
	}

	for i, expected := range expectedDelays {
		delay, ok := b.NextDelay()
		if !ok {
			t.Errorf("Call %d: NextDelay() should return ok=true", i+1)
		}
		if delay != expected {
			t.Errorf("Call %d: NextDelay() = %v, want %v", i+1, delay, expected)
		}
	}
}

func TestBackoff_NextDelay_MaxRetriesExceeded(t *testing.T) {
	t.Parallel()

	b := NewBackoff(BackoffConfig{
		MaxRetries:     3,
		InitialDelay:   1 * time.Second,
		JitterFraction: 0,
	})

	// Exhaust retries.
	for i := 0; i < 3; i++ {
		_, ok := b.NextDelay()
		if !ok {
			t.Errorf("Call %d: should return ok=true", i+1)
		}
	}

	// Fourth call should fail.
	_, ok := b.NextDelay()
	if ok {
		t.Error("NextDelay() should return ok=false after max retries exceeded")
	}
}

func TestBackoff_NextDelay_CappedAtMaxDelay(t *testing.T) {
	t.Parallel()

	b := NewBackoff(BackoffConfig{
		MaxRetries:     10,
		InitialDelay:   1 * time.Minute,
		MaxDelay:       5 * time.Minute,
		Multiplier:     10.0,
		JitterFraction: 0,
	})

	// First call: 1 minute.
	delay, _ := b.NextDelay()
	if delay != 1*time.Minute {
		t.Errorf("First delay = %v, want %v", delay, 1*time.Minute)
	}

	// Second call: 10 minutes, but capped at 5.
	delay, _ = b.NextDelay()
	if delay != 5*time.Minute {
		t.Errorf("Second delay = %v, want %v (capped)", delay, 5*time.Minute)
	}

	// Third call: still capped.
	delay, _ = b.NextDelay()
	if delay != 5*time.Minute {
		t.Errorf("Third delay = %v, want %v (capped)", delay, 5*time.Minute)
	}
}

func TestBackoff_Reset(t *testing.T) {
	t.Parallel()

	b := NewBackoff(BackoffConfig{
		MaxRetries:     5,
		InitialDelay:   1 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0,
	})

	// Advance a few times.
	b.NextDelay() // 1s
	b.NextDelay() // 2s
	b.NextDelay() // 4s

	// Reset.
	b.Reset()

	// Next call should be back to initial delay.
	delay, ok := b.NextDelay()
	if !ok {
		t.Error("NextDelay() should return ok=true after reset")
	}
	if delay != 1*time.Second {
		t.Errorf("After reset: NextDelay() = %v, want %v", delay, 1*time.Second)
	}
}

func TestBackoff_NextDelay_WithJitter(t *testing.T) {
	t.Parallel()

	b := NewBackoff(BackoffConfig{
		MaxRetries:     10,
		InitialDelay:   10 * time.Second,
		MaxDelay:       1 * time.Hour,
		Multiplier:     2.0,
		JitterFraction: 0.2, // 20% jitter.
	})

	// Run multiple times to verify jitter varies.
	baseDelay := 10 * time.Second
	minExpected := time.Duration(float64(baseDelay) * 0.8)
	maxExpected := time.Duration(float64(baseDelay) * 1.2)

	delay, _ := b.NextDelay()

	if delay < minExpected || delay > maxExpected {
		t.Errorf("NextDelay() = %v, should be in range [%v, %v]", delay, minExpected, maxExpected)
	}
}

func TestBackoff_Attempts(t *testing.T) {
	t.Parallel()

	b := NewBackoff(BackoffConfig{
		MaxRetries:     5,
		JitterFraction: 0,
	})

	if b.Attempts() != 0 {
		t.Errorf("Initial Attempts() = %d, want 0", b.Attempts())
	}

	b.NextDelay()
	if b.Attempts() != 1 {
		t.Errorf("After 1 call: Attempts() = %d, want 1", b.Attempts())
	}

	b.NextDelay()
	b.NextDelay()
	if b.Attempts() != 3 {
		t.Errorf("After 3 calls: Attempts() = %d, want 3", b.Attempts())
	}

	b.Reset()
	if b.Attempts() != 0 {
		t.Errorf("After Reset: Attempts() = %d, want 0", b.Attempts())
	}
}

func TestBackoffConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  BackoffConfig
		wantErr bool
	}{
		{
			name:    "empty config uses defaults",
			config:  BackoffConfig{},
			wantErr: false,
		},
		{
			name: "valid config",
			config: BackoffConfig{
				MaxRetries:     5,
				InitialDelay:   1 * time.Second,
				MaxDelay:       1 * time.Minute,
				Multiplier:     2.0,
				JitterFraction: 0.2,
			},
			wantErr: false,
		},
		{
			name: "negative jitter",
			config: BackoffConfig{
				JitterFraction: -0.1,
			},
			wantErr: true,
		},
		{
			name: "jitter over 1",
			config: BackoffConfig{
				JitterFraction: 1.5,
			},
			wantErr: true,
		},
		{
			name: "multiplier less than 1",
			config: BackoffConfig{
				Multiplier: 0.5,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
