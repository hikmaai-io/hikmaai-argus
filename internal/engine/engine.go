// ABOUTME: Lookup Engine combining Bloom filter and BadgerDB for hash lookups
// ABOUTME: Provides two-tier lookup: fast bloom rejection, then DB confirmation

package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/hikmaai-io/hikma-av/internal/types"
)

// EngineConfig holds configuration for the lookup engine.
type EngineConfig struct {
	// BadgerDB store configuration.
	StoreConfig StoreConfig

	// Bloom filter configuration.
	BloomConfig BloomConfig

	// RebuildBloomOnStart rebuilds the bloom filter from the database on startup.
	// This ensures the bloom filter is populated with existing signatures.
	RebuildBloomOnStart bool
}

// EngineStats contains statistics about the engine.
type EngineStats struct {
	// Number of signatures in the database.
	SignatureCount int64

	// Database size in bytes.
	StoreSizeBytes int64

	// Bloom filter statistics.
	BloomCapacity          uint
	BloomFalsePositiveRate float64
	BloomBitSetSize        uint64

	// Lookup statistics.
	TotalLookups     int64
	BloomRejections  int64
	BloomHits        int64
	StoreLookups     int64
	MalwareDetected  int64
}

// Engine is the main lookup engine combining Bloom filter and BadgerDB.
type Engine struct {
	store  *Store
	bloom  *BloomFilter
	config EngineConfig

	// Statistics counters.
	totalLookups    int64
	bloomRejections int64
	bloomHits       int64
	storeLookups    int64
	malwareDetected int64
}

// NewEngine creates a new lookup engine with the given configuration.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	store, err := NewStore(cfg.StoreConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	bloom := NewBloomFilter(cfg.BloomConfig)

	e := &Engine{
		store:  store,
		bloom:  bloom,
		config: cfg,
	}

	// Rebuild bloom filter from existing data if requested.
	if cfg.RebuildBloomOnStart {
		if err := e.RebuildBloomFilter(context.Background()); err != nil {
			store.Close()
			return nil, fmt.Errorf("failed to rebuild bloom filter on start: %w", err)
		}
	}

	return e, nil
}

// Close closes the engine and releases resources.
func (e *Engine) Close() error {
	return e.store.Close()
}

// Lookup looks up a hash and returns the result.
// The lookup follows a two-tier approach:
// 1. Check bloom filter (fast rejection if not present).
// 2. If bloom filter returns positive, check BadgerDB for confirmation.
func (e *Engine) Lookup(ctx context.Context, hash types.Hash) (types.Result, error) {
	start := time.Now()
	e.totalLookups++

	// Step 1: Check bloom filter.
	bloomHit := e.bloom.Test(hash)
	if !bloomHit {
		// Bloom filter says "definitely not present".
		e.bloomRejections++
		result := types.NewUnknownResult(hash).
			WithLookupTime(float64(time.Since(start).Microseconds()) / 1000).
			WithBloomHit(false)
		return result, nil
	}

	e.bloomHits++

	// Step 2: Bloom filter says "maybe present", check store.
	e.storeLookups++
	sig, err := e.store.Get(ctx, hash)
	if err != nil {
		result := types.NewErrorResult(hash, err.Error()).
			WithLookupTime(float64(time.Since(start).Microseconds()) / 1000).
			WithBloomHit(true)
		return result, err
	}

	elapsed := float64(time.Since(start).Microseconds()) / 1000

	if sig == nil {
		// False positive from bloom filter.
		result := types.NewUnknownResult(hash).
			WithLookupTime(elapsed).
			WithBloomHit(true)
		return result, nil
	}

	// Malware detected.
	e.malwareDetected++
	result := types.NewMalwareResult(hash, sig).
		WithLookupTime(elapsed).
		WithBloomHit(true)
	return result, nil
}

// AddSignature adds a signature to both the bloom filter and the store.
func (e *Engine) AddSignature(ctx context.Context, sig *types.Signature) error {
	if sig == nil {
		return fmt.Errorf("signature is nil")
	}

	// Add to store first.
	if err := e.store.Put(ctx, sig); err != nil {
		return fmt.Errorf("failed to store signature: %w", err)
	}

	// Add all hashes to bloom filter.
	for _, hash := range sig.GetHashes() {
		e.bloom.Add(hash)
	}

	return nil
}

// BatchAddSignatures adds multiple signatures efficiently.
func (e *Engine) BatchAddSignatures(ctx context.Context, sigs []*types.Signature) error {
	if len(sigs) == 0 {
		return nil
	}

	// Batch store operation.
	if err := e.store.BatchPut(ctx, sigs); err != nil {
		return fmt.Errorf("failed to batch store signatures: %w", err)
	}

	// Add all hashes to bloom filter.
	for _, sig := range sigs {
		if sig == nil {
			continue
		}
		for _, hash := range sig.GetHashes() {
			e.bloom.Add(hash)
		}
	}

	return nil
}

// RebuildBloomFilter rebuilds the bloom filter from the store.
// This is useful after importing signatures directly to the store.
func (e *Engine) RebuildBloomFilter(ctx context.Context) error {
	// Create a new bloom filter.
	newBloom := NewBloomFilter(e.config.BloomConfig)

	// Iterate over all SHA256 hashes in the store.
	err := e.store.IterateHashes(ctx, types.HashTypeSHA256, func(hashValue string) error {
		hash := types.Hash{Type: types.HashTypeSHA256, Value: hashValue}
		newBloom.Add(hash)
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to iterate SHA256 hashes: %w", err)
	}

	// Iterate over SHA1 hashes.
	err = e.store.IterateHashes(ctx, types.HashTypeSHA1, func(hashValue string) error {
		hash := types.Hash{Type: types.HashTypeSHA1, Value: hashValue}
		newBloom.Add(hash)
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to iterate SHA1 hashes: %w", err)
	}

	// Iterate over MD5 hashes.
	err = e.store.IterateHashes(ctx, types.HashTypeMD5, func(hashValue string) error {
		hash := types.Hash{Type: types.HashTypeMD5, Value: hashValue}
		newBloom.Add(hash)
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to iterate MD5 hashes: %w", err)
	}

	// Atomic swap.
	e.bloom.Swap(newBloom)

	return nil
}

// Stats returns statistics about the engine.
func (e *Engine) Stats(ctx context.Context) (*EngineStats, error) {
	storeStats, err := e.store.Stats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get store stats: %w", err)
	}

	bloomStats := e.bloom.Stats()

	return &EngineStats{
		SignatureCount:         storeStats.SignatureCount,
		StoreSizeBytes:         storeStats.SizeBytes,
		BloomCapacity:          bloomStats.Capacity,
		BloomFalsePositiveRate: bloomStats.FalsePositiveRate,
		BloomBitSetSize:        bloomStats.BitSetSize,
		TotalLookups:           e.totalLookups,
		BloomRejections:        e.bloomRejections,
		BloomHits:              e.bloomHits,
		StoreLookups:           e.storeLookups,
		MalwareDetected:        e.malwareDetected,
	}, nil
}

// GetStore returns the underlying store (for advanced operations).
func (e *Engine) GetStore() *Store {
	return e.store
}

// GetBloomFilter returns the underlying bloom filter (for advanced operations).
func (e *Engine) GetBloomFilter() *BloomFilter {
	return e.bloom
}

// SaveBloomFilter saves the bloom filter to a file.
func (e *Engine) SaveBloomFilter(path string) error {
	return e.bloom.SaveToFile(path)
}

// LoadBloomFilter loads a bloom filter from a file.
func (e *Engine) LoadBloomFilter(path string) error {
	loaded, err := LoadBloomFilter(path)
	if err != nil {
		return fmt.Errorf("failed to load bloom filter: %w", err)
	}
	e.bloom.Swap(loaded)
	return nil
}
