// ABOUTME: ScanCache caches scan results by file hash in BadgerDB
// ABOUTME: Avoids re-scanning files with TTL-based expiration

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/hikmaai-io/hikma-av/internal/types"
)

const scanCachePrefix = "scan:"

// ScanCache caches scan results by file hash.
type ScanCache struct {
	db  *badger.DB
	ttl time.Duration
}

// NewScanCache creates a new scan cache.
func NewScanCache(cfg StoreConfig, ttl time.Duration) (*ScanCache, error) {
	opts := badger.DefaultOptions(cfg.Path)

	if cfg.InMemory {
		opts = opts.WithInMemory(true)
	}

	if cfg.SyncWrites {
		opts = opts.WithSyncWrites(true)
	}

	if cfg.Logger != nil {
		opts = opts.WithLogger(cfg.Logger)
	} else {
		opts = opts.WithLogger(nil)
	}

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("opening badger db: %w", err)
	}

	return &ScanCache{
		db:  db,
		ttl: ttl,
	}, nil
}

// Close closes the database.
func (c *ScanCache) Close() error {
	if c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Put stores a scan result with TTL.
func (c *ScanCache) Put(ctx context.Context, fileHash string, result *types.ScanResult) error {
	if result == nil {
		return fmt.Errorf("result is nil")
	}

	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling result: %w", err)
	}

	return c.db.Update(func(txn *badger.Txn) error {
		key := scanCachePrefix + fileHash
		entry := badger.NewEntry([]byte(key), data)

		if c.ttl > 0 {
			entry = entry.WithTTL(c.ttl)
		}

		return txn.SetEntry(entry)
	})
}

// Get retrieves a cached scan result.
// Returns (result, true, nil) if found, (nil, false, nil) if not found.
func (c *ScanCache) Get(ctx context.Context, fileHash string) (*types.ScanResult, bool, error) {
	var result *types.ScanResult

	err := c.db.View(func(txn *badger.Txn) error {
		key := scanCachePrefix + fileHash
		item, err := txn.Get([]byte(key))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return fmt.Errorf("getting cache entry: %w", err)
		}

		return item.Value(func(val []byte) error {
			result = &types.ScanResult{}
			if err := json.Unmarshal(val, result); err != nil {
				return fmt.Errorf("unmarshaling result: %w", err)
			}
			return nil
		})
	})

	if err != nil {
		return nil, false, err
	}

	return result, result != nil, nil
}

// Delete removes a cached result.
func (c *ScanCache) Delete(ctx context.Context, fileHash string) error {
	return c.db.Update(func(txn *badger.Txn) error {
		key := scanCachePrefix + fileHash
		err := txn.Delete([]byte(key))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		return err
	})
}

// Clear removes all cached results.
func (c *ScanCache) Clear(ctx context.Context) error {
	return c.db.DropPrefix([]byte(scanCachePrefix))
}

// Count returns the number of cached results.
func (c *ScanCache) Count(ctx context.Context) (int64, error) {
	var count int64

	err := c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = []byte(scanCachePrefix)
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		return nil
	})

	return count, err
}

// TTL returns the cache TTL.
func (c *ScanCache) TTL() time.Duration {
	return c.ttl
}
