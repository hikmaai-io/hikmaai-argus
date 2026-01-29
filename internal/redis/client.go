// ABOUTME: Redis client wrapper with configurable key prefix for multi-tenant support
// ABOUTME: Provides connection pooling, health checks, and prefixed key operations

package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds Redis client configuration.
type Config struct {
	// Addr is the Redis server address (host:port).
	Addr string

	// Password for Redis authentication (optional).
	Password string

	// DB is the Redis database number.
	DB int

	// Prefix is prepended to all keys for multi-tenant isolation.
	// Example: "argus:" results in keys like "argus:job:123".
	Prefix string

	// PoolSize is the number of connections in the pool.
	PoolSize int

	// ReadTimeout for Redis operations.
	ReadTimeout time.Duration

	// WriteTimeout for Redis operations.
	WriteTimeout time.Duration
}

// setDefaults applies default values to unset fields.
func (c *Config) setDefaults() {
	if c.PoolSize == 0 {
		c.PoolSize = 10
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 5 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 5 * time.Second
	}
}

// Client wraps a Redis client with prefix support.
type Client struct {
	rdb    *redis.Client
	prefix string
}

// NewClient creates a new Redis client with the given configuration.
// It verifies connectivity by sending a PING command.
func NewClient(cfg Config) (*Client, error) {
	cfg.setDefaults()

	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	// Verify connectivity.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ReadTimeout)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("connecting to redis %s: %w", cfg.Addr, err)
	}

	return &Client{
		rdb:    rdb,
		prefix: cfg.Prefix,
	}, nil
}

// PrefixedKey returns the key with the configured prefix applied.
func (c *Client) PrefixedKey(key string) string {
	return c.prefix + key
}

// Ping verifies connectivity to Redis.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("pinging redis: %w", err)
	}
	return nil
}

// Set stores a value with the given key and TTL.
// The key is automatically prefixed.
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	prefixedKey := c.PrefixedKey(key)
	if err := c.rdb.Set(ctx, prefixedKey, value, ttl).Err(); err != nil {
		return fmt.Errorf("setting key %s: %w", prefixedKey, err)
	}
	return nil
}

// Get retrieves a value by key.
// The key is automatically prefixed.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	prefixedKey := c.PrefixedKey(key)
	val, err := c.rdb.Get(ctx, prefixedKey).Result()
	if err != nil {
		return "", fmt.Errorf("getting key %s: %w", prefixedKey, err)
	}
	return val, nil
}

// Close closes the Redis connection.
func (c *Client) Close() error {
	if err := c.rdb.Close(); err != nil {
		return fmt.Errorf("closing redis client: %w", err)
	}
	return nil
}

// Redis returns the underlying go-redis client for advanced operations.
// Use with caution; prefer using Client methods for prefix support.
func (c *Client) Redis() *redis.Client {
	return c.rdb
}

// Prefix returns the configured key prefix.
func (c *Client) Prefix() string {
	return c.prefix
}
