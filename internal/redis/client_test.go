// ABOUTME: Unit tests for Redis client with configurable prefix support
// ABOUTME: Uses miniredis for isolated testing without external Redis

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Addr:   mr.Addr(),
				Prefix: "test:",
			},
			wantErr: false,
		},
		{
			name: "empty prefix uses default",
			cfg: Config{
				Addr:   mr.Addr(),
				Prefix: "",
			},
			wantErr: false,
		},
		{
			name: "invalid address",
			cfg: Config{
				Addr:   "invalid:99999",
				Prefix: "test:",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := NewClient(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Error("NewClient() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			defer client.Close()

			if client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

func TestClient_Ping(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	if err := client.Ping(ctx); err != nil {
		t.Errorf("Ping() error = %v", err)
	}
}

func TestClient_PrefixedKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix string
		key    string
		want   string
	}{
		{
			name:   "with prefix",
			prefix: "argus:",
			key:    "job:123",
			want:   "argus:job:123",
		},
		{
			name:   "empty prefix",
			prefix: "",
			key:    "job:123",
			want:   "job:123",
		},
		{
			name:   "prefix without colon",
			prefix: "test",
			key:    "key",
			want:   "testkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mr := miniredis.RunT(t)
			client, err := NewClient(Config{
				Addr:   mr.Addr(),
				Prefix: tt.prefix,
			})
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			defer client.Close()

			got := client.PrefixedKey(tt.key)
			if got != tt.want {
				t.Errorf("PrefixedKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClient_SetGet(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Set a value.
	if err := client.Set(ctx, "mykey", "myvalue", time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Get the value.
	val, err := client.Get(ctx, "mykey")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if val != "myvalue" {
		t.Errorf("Get() = %q, want %q", val, "myvalue")
	}

	// Verify prefix was applied in Redis.
	actualKey := "test:mykey"
	if !mr.Exists(actualKey) {
		t.Errorf("key %q not found in Redis (prefix not applied)", actualKey)
	}
}

func TestClient_Close(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// After close, Ping should fail.
	ctx := context.Background()
	if err := client.Ping(ctx); err == nil {
		t.Error("Ping() after Close() expected error, got nil")
	}
}

func TestConfig_Defaults(t *testing.T) {
	t.Parallel()

	cfg := Config{}
	cfg.setDefaults()

	if cfg.PoolSize != 10 {
		t.Errorf("PoolSize = %d, want 10", cfg.PoolSize)
	}
	if cfg.ReadTimeout != 5*time.Second {
		t.Errorf("ReadTimeout = %v, want 5s", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 5*time.Second {
		t.Errorf("WriteTimeout = %v, want 5s", cfg.WriteTimeout)
	}
}
