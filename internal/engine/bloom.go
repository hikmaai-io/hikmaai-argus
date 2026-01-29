// ABOUTME: Bloom filter wrapper with atomic pointer swap for hot reloads
// ABOUTME: Thread-safe probabilistic filter for fast hash rejection

package engine

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/bits-and-blooms/bloom/v3"

	"github.com/hikmaai-io/hikma-av/internal/types"
)

// BloomConfig holds configuration for the Bloom filter.
type BloomConfig struct {
	// Expected number of items to be added.
	ExpectedItems uint

	// Desired false positive rate (e.g., 0.01 for 1%).
	FalsePositiveRate float64
}

// BloomStats contains statistics about the Bloom filter.
type BloomStats struct {
	// Configured capacity.
	Capacity uint

	// Configured false positive rate.
	FalsePositiveRate float64

	// Size of the bit set in bytes.
	BitSetSize uint64

	// Number of hash functions used.
	HashFunctions uint
}

// BloomFilter wraps a Bloom filter with atomic swap capability.
type BloomFilter struct {
	filter atomic.Pointer[bloom.BloomFilter]
	mu     sync.RWMutex // Protects writes to the filter
	config BloomConfig
}

// NewBloomFilter creates a new Bloom filter with the given configuration.
func NewBloomFilter(cfg BloomConfig) *BloomFilter {
	bf := &BloomFilter{
		config: cfg,
	}

	// Create the underlying filter.
	f := bloom.NewWithEstimates(cfg.ExpectedItems, cfg.FalsePositiveRate)
	bf.filter.Store(f)

	return bf
}

// Add adds a hash to the filter.
func (bf *BloomFilter) Add(hash types.Hash) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	f := bf.filter.Load()
	if f != nil {
		f.Add([]byte(hash.Key()))
	}
}

// Test checks if a hash might be in the filter.
// Returns true if the hash might be present (could be false positive).
// Returns false if the hash is definitely not present.
func (bf *BloomFilter) Test(hash types.Hash) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	f := bf.filter.Load()
	if f == nil {
		return false
	}
	return f.Test([]byte(hash.Key()))
}

// Swap atomically replaces the internal filter with the one from another BloomFilter.
func (bf *BloomFilter) Swap(other *BloomFilter) {
	if other == nil {
		return
	}
	bf.mu.Lock()
	defer bf.mu.Unlock()
	newFilter := other.filter.Load()
	if newFilter != nil {
		bf.filter.Store(newFilter)
	}
}

// SwapFilter atomically replaces the internal filter with a new one.
func (bf *BloomFilter) SwapFilter(f *bloom.BloomFilter) {
	if f != nil {
		bf.mu.Lock()
		defer bf.mu.Unlock()
		bf.filter.Store(f)
	}
}

// Clear clears the filter by creating a new empty one.
func (bf *BloomFilter) Clear() {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	f := bloom.NewWithEstimates(bf.config.ExpectedItems, bf.config.FalsePositiveRate)
	bf.filter.Store(f)
}

// Stats returns statistics about the filter.
func (bf *BloomFilter) Stats() BloomStats {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	f := bf.filter.Load()
	if f == nil {
		return BloomStats{
			Capacity:          bf.config.ExpectedItems,
			FalsePositiveRate: bf.config.FalsePositiveRate,
		}
	}

	return BloomStats{
		Capacity:          bf.config.ExpectedItems,
		FalsePositiveRate: bf.config.FalsePositiveRate,
		BitSetSize:        uint64(f.Cap() / 8),
		HashFunctions:     f.K(),
	}
}

// SaveToFile saves the filter to a file.
func (bf *BloomFilter) SaveToFile(path string) error {
	bf.mu.RLock()
	f := bf.filter.Load()
	bf.mu.RUnlock()
	if f == nil {
		return fmt.Errorf("filter is nil")
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = f.WriteTo(file)
	if err != nil {
		return fmt.Errorf("failed to write filter: %w", err)
	}

	return nil
}

// LoadBloomFilter loads a Bloom filter from a file.
func LoadBloomFilter(path string) (*BloomFilter, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	f := &bloom.BloomFilter{}
	_, err = f.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read filter: %w", err)
	}

	bf := &BloomFilter{
		config: BloomConfig{
			// Estimate from loaded filter.
			ExpectedItems:   uint(f.Cap() / 10), // Rough estimate.
			FalsePositiveRate: 0.01,              // Default; actual rate depends on items.
		},
	}
	bf.filter.Store(f)

	return bf, nil
}

// GetFilter returns the underlying Bloom filter (for advanced operations).
// Note: The returned filter should be used read-only to maintain thread safety.
func (bf *BloomFilter) GetFilter() *bloom.BloomFilter {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.filter.Load()
}
