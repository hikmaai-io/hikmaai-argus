// ABOUTME: Per-package vulnerability cache using BadgerDB
// ABOUTME: Caches scan results with TTL to avoid redundant Trivy queries

package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// Cache key prefix for Trivy package vulnerabilities.
const cacheKeyPrefix = "trivy:pkg:"

// CacheConfig holds configuration for the vulnerability cache.
type CacheConfig struct {
	// Path to the BadgerDB directory. Ignored if InMemory is true.
	Path string

	// InMemory enables in-memory storage (for testing).
	InMemory bool

	// TTL is the time-to-live for cached entries.
	TTL time.Duration
}

// CacheEntry represents a cached vulnerability scan result.
type CacheEntry struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	ScannedAt       time.Time       `json:"scanned_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
}

// Cache stores per-package vulnerability scan results.
type Cache struct {
	db  *badger.DB
	ttl time.Duration
}

// NewCache creates a new vulnerability cache with the given configuration.
func NewCache(cfg CacheConfig) (*Cache, error) {
	opts := badger.DefaultOptions(cfg.Path)
	opts.Logger = nil // Disable badger logging

	if cfg.InMemory {
		opts = opts.WithInMemory(true)
	}

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache database: %w", err)
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 1 * time.Hour
	}

	return &Cache{
		db:  db,
		ttl: ttl,
	}, nil
}

// Get retrieves cached vulnerabilities for a package.
// Returns the vulnerabilities, whether the entry was found, and any error.
func (c *Cache) Get(_ context.Context, pkg Package) ([]Vulnerability, bool, error) {
	key := []byte(pkg.CacheKey())

	var entry CacheEntry
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &entry)
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to get cache entry: %w", err)
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false, nil
	}

	return entry.Vulnerabilities, true, nil
}

// Set stores vulnerabilities for a package in the cache.
func (c *Cache) Set(_ context.Context, pkg Package, vulns []Vulnerability) error {
	key := []byte(pkg.CacheKey())
	now := time.Now()

	entry := CacheEntry{
		Vulnerabilities: vulns,
		ScannedAt:       now,
		ExpiresAt:       now.Add(c.ttl),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to encode cache entry: %w", err)
	}

	err = c.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(key, data).WithTTL(c.ttl)
		return txn.SetEntry(e)
	})
	if err != nil {
		return fmt.Errorf("failed to set cache entry: %w", err)
	}

	return nil
}

// Delete removes a package from the cache.
func (c *Cache) Delete(_ context.Context, pkg Package) error {
	key := []byte(pkg.CacheKey())

	err := c.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
	if err != nil && err != badger.ErrKeyNotFound {
		return fmt.Errorf("failed to delete cache entry: %w", err)
	}

	return nil
}

// GetMultiple retrieves cached results for multiple packages.
// Returns a map of cached results and a slice of packages not in cache.
func (c *Cache) GetMultiple(ctx context.Context, packages []Package) (map[string][]Vulnerability, []Package) {
	cached := make(map[string][]Vulnerability)
	var uncached []Package

	for _, pkg := range packages {
		vulns, found, err := c.Get(ctx, pkg)
		if err != nil || !found {
			uncached = append(uncached, pkg)
			continue
		}
		cached[pkg.CacheKey()] = vulns
	}

	return cached, uncached
}

// Cleanup removes expired entries from the cache.
// Returns the number of entries deleted.
func (c *Cache) Cleanup(_ context.Context) (int, error) {
	deleted := 0
	now := time.Now()

	err := c.db.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte(cacheKeyPrefix)
		var keysToDelete [][]byte

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			err := item.Value(func(val []byte) error {
				var entry CacheEntry
				if err := json.Unmarshal(val, &entry); err != nil {
					return nil // Skip malformed entries
				}

				if now.After(entry.ExpiresAt) {
					keyCopy := make([]byte, len(item.Key()))
					copy(keyCopy, item.Key())
					keysToDelete = append(keysToDelete, keyCopy)
				}
				return nil
			})
			if err != nil {
				continue
			}
		}

		for _, key := range keysToDelete {
			if err := txn.Delete(key); err != nil {
				continue
			}
			deleted++
		}

		return nil
	})
	if err != nil {
		return deleted, fmt.Errorf("failed to cleanup cache: %w", err)
	}

	return deleted, nil
}

// Close closes the cache database.
func (c *Cache) Close() error {
	return c.db.Close()
}

// TTL returns the configured TTL.
func (c *Cache) TTL() time.Duration {
	return c.ttl
}
