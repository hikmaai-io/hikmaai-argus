// ABOUTME: Tests for DB update configuration types
// ABOUTME: Validates defaults, intervals, and retry settings

package config

import (
	"testing"
	"time"
)

func TestDBUpdateConfig_Defaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultDBUpdateConfig()

	if cfg.Enabled {
		t.Error("Enabled should be false by default")
	}
	if !cfg.ClamAV.Enabled {
		t.Error("ClamAV.Enabled should be true by default")
	}
	if cfg.ClamAV.Interval != 1*time.Hour {
		t.Errorf("ClamAV.Interval = %v, want 1h", cfg.ClamAV.Interval)
	}
	if !cfg.Trivy.Enabled {
		t.Error("Trivy.Enabled should be true by default")
	}
	if cfg.Trivy.Interval != 6*time.Hour {
		t.Errorf("Trivy.Interval = %v, want 6h", cfg.Trivy.Interval)
	}
	if !cfg.Signatures.Enabled {
		t.Error("Signatures.Enabled should be true by default")
	}
	if cfg.Signatures.Interval != 1*time.Hour {
		t.Errorf("Signatures.Interval = %v, want 1h", cfg.Signatures.Interval)
	}
}

func TestDBUpdateSourceConfig_Defaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultDBUpdateSourceConfig()

	if !cfg.Enabled {
		t.Error("Enabled should be true by default")
	}
	if cfg.Interval != 1*time.Hour {
		t.Errorf("Interval = %v, want 1h", cfg.Interval)
	}
}

func TestRetryConfig_Defaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultRetryConfig()

	if cfg.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", cfg.MaxRetries)
	}
	if cfg.InitialDelay != 30*time.Second {
		t.Errorf("InitialDelay = %v, want 30s", cfg.InitialDelay)
	}
	if cfg.MaxDelay != 30*time.Minute {
		t.Errorf("MaxDelay = %v, want 30m", cfg.MaxDelay)
	}
	if cfg.Multiplier != 2.0 {
		t.Errorf("Multiplier = %f, want 2.0", cfg.Multiplier)
	}
}

func TestDBUpdateSourceConfig_GetRetry(t *testing.T) {
	t.Parallel()

	t.Run("uses_custom_retry", func(t *testing.T) {
		t.Parallel()

		custom := &RetryConfig{
			MaxRetries:   10,
			InitialDelay: 1 * time.Minute,
		}
		cfg := DBUpdateSourceConfig{
			Enabled:  true,
			Interval: 2 * time.Hour,
			Retry:    custom,
		}

		got := cfg.GetRetry()
		if got.MaxRetries != 10 {
			t.Errorf("GetRetry().MaxRetries = %d, want 10", got.MaxRetries)
		}
	})

	t.Run("uses_default_retry", func(t *testing.T) {
		t.Parallel()

		cfg := DBUpdateSourceConfig{
			Enabled:  true,
			Interval: 2 * time.Hour,
			Retry:    nil,
		}

		got := cfg.GetRetry()
		if got.MaxRetries != 5 {
			t.Errorf("GetRetry().MaxRetries = %d, want 5 (default)", got.MaxRetries)
		}
	})
}
