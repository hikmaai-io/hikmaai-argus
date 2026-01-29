// ABOUTME: BadgerDB wrapper for signature storage
// ABOUTME: Provides Put, Get, BatchPut, Delete, and iteration operations

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dgraph-io/badger/v4"

	"github.com/hikmaai-io/hikma-av/internal/types"
)

// StoreConfig holds configuration for the BadgerDB store.
type StoreConfig struct {
	// Path to the database directory. Required unless InMemory is true.
	Path string

	// InMemory runs the database in memory (for testing).
	InMemory bool

	// SyncWrites enables synchronous writes (slower but safer).
	SyncWrites bool

	// Logger for BadgerDB operations.
	Logger badger.Logger
}

// StoreStats contains statistics about the store.
type StoreStats struct {
	// Number of signatures in the database.
	SignatureCount int64

	// Database size in bytes.
	SizeBytes int64

	// Number of LSM levels.
	LSMLevels int
}

// Store wraps BadgerDB for signature storage.
type Store struct {
	db     *badger.DB
	config StoreConfig
}

// NewStore creates a new BadgerDB store with the given configuration.
func NewStore(cfg StoreConfig) (*Store, error) {
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
		opts = opts.WithLogger(nil) // Disable logging by default.
	}

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger db: %w", err)
	}

	return &Store{
		db:     db,
		config: cfg,
	}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Put stores a signature in the database.
// The signature is stored at all available hash keys (SHA256, SHA1, MD5).
func (s *Store) Put(ctx context.Context, sig *types.Signature) error {
	if sig == nil {
		return fmt.Errorf("signature is nil")
	}

	data, err := json.Marshal(sig)
	if err != nil {
		return fmt.Errorf("failed to marshal signature: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		// Store at all available hash keys (denormalized for O(1) lookup).
		keys := s.keysForSignature(sig)
		for _, key := range keys {
			if err := txn.Set([]byte(key), data); err != nil {
				return fmt.Errorf("failed to set key %s: %w", key, err)
			}
		}
		return nil
	})
}

// Get retrieves a signature by hash.
// Returns nil if the hash is not found.
func (s *Store) Get(ctx context.Context, hash types.Hash) (*types.Signature, error) {
	var sig *types.Signature

	err := s.db.View(func(txn *badger.Txn) error {
		key := hash.Key()
		item, err := txn.Get([]byte(key))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get key %s: %w", key, err)
		}

		return item.Value(func(val []byte) error {
			sig = &types.Signature{}
			if err := json.Unmarshal(val, sig); err != nil {
				return fmt.Errorf("failed to unmarshal signature: %w", err)
			}
			return nil
		})
	})

	return sig, err
}

// BatchPut stores multiple signatures in a single transaction.
func (s *Store) BatchPut(ctx context.Context, sigs []*types.Signature) error {
	if len(sigs) == 0 {
		return nil
	}

	wb := s.db.NewWriteBatch()
	defer wb.Cancel()

	for _, sig := range sigs {
		if sig == nil {
			continue
		}

		data, err := json.Marshal(sig)
		if err != nil {
			return fmt.Errorf("failed to marshal signature: %w", err)
		}

		keys := s.keysForSignature(sig)
		for _, key := range keys {
			if err := wb.Set([]byte(key), data); err != nil {
				return fmt.Errorf("failed to set key %s: %w", key, err)
			}
		}
	}

	return wb.Flush()
}

// Delete removes a signature by hash.
func (s *Store) Delete(ctx context.Context, hash types.Hash) error {
	return s.db.Update(func(txn *badger.Txn) error {
		key := hash.Key()
		return txn.Delete([]byte(key))
	})
}

// Stats returns statistics about the store.
func (s *Store) Stats(ctx context.Context) (*StoreStats, error) {
	stats := &StoreStats{}

	// Count signatures (only SHA256 keys to avoid duplicates).
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte("sha256:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			stats.SignatureCount++
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to count signatures: %w", err)
	}

	// Get LSM size.
	lsm, vlog := s.db.Size()
	stats.SizeBytes = lsm + vlog

	return stats, nil
}

// IterateHashes iterates over all hashes of the specified type.
func (s *Store) IterateHashes(ctx context.Context, hashType types.HashType, fn func(hash string) error) error {
	prefix := hashType.String() + ":"

	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		prefixBytes := []byte(prefix)
		for it.Seek(prefixBytes); it.ValidForPrefix(prefixBytes); it.Next() {
			key := string(it.Item().Key())
			hash := strings.TrimPrefix(key, prefix)
			if err := fn(hash); err != nil {
				return err
			}
		}
		return nil
	})
}

// Compact triggers garbage collection on the database.
func (s *Store) Compact() error {
	return s.db.RunValueLogGC(0.5)
}

// keysForSignature returns all storage keys for a signature.
func (s *Store) keysForSignature(sig *types.Signature) []string {
	keys := make([]string, 0, 3)

	if sig.SHA256 != "" {
		keys = append(keys, "sha256:"+sig.SHA256)
	}
	if sig.SHA1 != "" {
		keys = append(keys, "sha1:"+sig.SHA1)
	}
	if sig.MD5 != "" {
		keys = append(keys, "md5:"+sig.MD5)
	}

	return keys
}
