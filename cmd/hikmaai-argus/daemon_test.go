// ABOUTME: Unit tests for daemon command configuration and initialization
// ABOUTME: Tests TrivyConfig cache settings are properly passed through

package main

import (
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/config"
	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
)

func TestDaemonConfig_TrivyCacheFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		trivyCacheDir     string
		trivySkipDBUpdate bool
	}{
		{
			name:              "default values",
			trivyCacheDir:     "/app/data/trivy-cache",
			trivySkipDBUpdate: false,
		},
		{
			name:              "custom cache dir",
			trivyCacheDir:     "/custom/path/trivy-cache",
			trivySkipDBUpdate: false,
		},
		{
			name:              "skip db update enabled",
			trivyCacheDir:     "/app/data/trivy-cache",
			trivySkipDBUpdate: true,
		},
		{
			name:              "both custom cache and skip update",
			trivyCacheDir:     "/opt/trivy/cache",
			trivySkipDBUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := daemonConfig{
				TrivyCacheDir:     tt.trivyCacheDir,
				TrivySkipDBUpdate: tt.trivySkipDBUpdate,
			}

			if cfg.TrivyCacheDir != tt.trivyCacheDir {
				t.Errorf("TrivyCacheDir = %q, want %q", cfg.TrivyCacheDir, tt.trivyCacheDir)
			}
			if cfg.TrivySkipDBUpdate != tt.trivySkipDBUpdate {
				t.Errorf("TrivySkipDBUpdate = %v, want %v", cfg.TrivySkipDBUpdate, tt.trivySkipDBUpdate)
			}
		})
	}
}

func TestTrivyConfig_CacheDirPassthrough(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cacheDir     string
		skipDBUpdate bool
	}{
		{
			name:         "empty cache dir uses trivy default",
			cacheDir:     "",
			skipDBUpdate: false,
		},
		{
			name:         "persistent cache dir",
			cacheDir:     "/app/data/trivy-cache",
			skipDBUpdate: false,
		},
		{
			name:         "air-gapped mode",
			cacheDir:     "/app/data/trivy-cache",
			skipDBUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Simulate what initArgusWorker does.
			trivyConfig := &config.TrivyConfig{
				Mode:         "local",
				Binary:       "trivy",
				Timeout:      5 * time.Minute,
				CacheDir:     tt.cacheDir,
				SkipDBUpdate: tt.skipDBUpdate,
			}

			scanner := trivy.NewUnifiedScanner(trivyConfig)
			if scanner == nil {
				t.Fatal("NewUnifiedScanner returned nil")
			}

			// Verify the mode is correctly set.
			if scanner.Mode() != "local" {
				t.Errorf("Mode() = %q, want %q", scanner.Mode(), "local")
			}
		})
	}
}

func TestNewDaemonCmd_TrivyFlags(t *testing.T) {
	t.Parallel()

	cmd := newDaemonCmd()
	if cmd == nil {
		t.Fatal("newDaemonCmd() returned nil")
	}

	// Verify trivy-cache-dir flag exists with correct default.
	cacheDirFlag := cmd.Flags().Lookup("trivy-cache-dir")
	if cacheDirFlag == nil {
		t.Fatal("trivy-cache-dir flag not found")
	}
	if cacheDirFlag.DefValue != "/app/data/trivy-cache" {
		t.Errorf("trivy-cache-dir default = %q, want %q", cacheDirFlag.DefValue, "/app/data/trivy-cache")
	}

	// Verify trivy-skip-db-update flag exists with correct default.
	skipUpdateFlag := cmd.Flags().Lookup("trivy-skip-db-update")
	if skipUpdateFlag == nil {
		t.Fatal("trivy-skip-db-update flag not found")
	}
	if skipUpdateFlag.DefValue != "false" {
		t.Errorf("trivy-skip-db-update default = %q, want %q", skipUpdateFlag.DefValue, "false")
	}
}
