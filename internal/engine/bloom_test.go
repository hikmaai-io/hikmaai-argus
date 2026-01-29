// ABOUTME: Tests for Bloom filter wrapper with atomic swap
// ABOUTME: Covers add, test, rebuild, persistence, and concurrent access

package engine_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestBloomFilter_AddAndTest(t *testing.T) {
	t.Parallel()

	bf := engine.NewBloomFilter(engine.BloomConfig{
		ExpectedItems:   1000,
		FalsePositiveRate: 0.01,
	})

	hash := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	}

	// Test before adding.
	if bf.Test(hash) {
		t.Error("Test() should return false for unadded hash")
	}

	// Add hash.
	bf.Add(hash)

	// Test after adding.
	if !bf.Test(hash) {
		t.Error("Test() should return true for added hash")
	}
}

func TestBloomFilter_TestUnknownHash(t *testing.T) {
	t.Parallel()

	bf := engine.NewBloomFilter(engine.BloomConfig{
		ExpectedItems:   1000,
		FalsePositiveRate: 0.01,
	})

	// Add some hashes.
	for i := 0; i < 100; i++ {
		hash := types.Hash{
			Type:  types.HashTypeSHA256,
			Value: hashFromInt(i),
		}
		bf.Add(hash)
	}

	// Test unknown hash.
	unknown := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}

	// Should return false (with high probability).
	if bf.Test(unknown) {
		t.Log("False positive detected (acceptable for probabilistic filter)")
	}
}

func TestBloomFilter_AtomicSwap(t *testing.T) {
	t.Parallel()

	bf := engine.NewBloomFilter(engine.BloomConfig{
		ExpectedItems:   1000,
		FalsePositiveRate: 0.01,
	})

	// Add initial hash.
	hash1 := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	bf.Add(hash1)

	// Create new filter with different data.
	newBf := engine.NewBloomFilter(engine.BloomConfig{
		ExpectedItems:   1000,
		FalsePositiveRate: 0.01,
	})
	hash2 := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	newBf.Add(hash2)

	// Swap the internal filter.
	bf.Swap(newBf)

	// Old hash should not be found.
	if bf.Test(hash1) {
		t.Error("Test(hash1) should return false after swap")
	}

	// New hash should be found.
	if !bf.Test(hash2) {
		t.Error("Test(hash2) should return true after swap")
	}
}

func TestBloomFilter_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	bf := engine.NewBloomFilter(engine.BloomConfig{
		ExpectedItems:   10000,
		FalsePositiveRate: 0.01,
	})

	// Pre-add some hashes.
	for i := 0; i < 100; i++ {
		hash := types.Hash{
			Type:  types.HashTypeSHA256,
			Value: hashFromInt(i),
		}
		bf.Add(hash)
	}

	var wg sync.WaitGroup
	workers := 10
	iterations := 1000

	// Concurrent readers.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				hash := types.Hash{
					Type:  types.HashTypeSHA256,
					Value: hashFromInt(i % 200),
				}
				_ = bf.Test(hash)
			}
		}()
	}

	// Concurrent writers (fewer).
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				hash := types.Hash{
					Type:  types.HashTypeSHA256,
					Value: hashFromInt(1000 + workerID*100 + i),
				}
				bf.Add(hash)
			}
		}(w)
	}

	wg.Wait()
}

func TestBloomFilter_Persistence(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bloom.dat")

	// Create and populate filter.
	bf := engine.NewBloomFilter(engine.BloomConfig{
		ExpectedItems:   1000,
		FalsePositiveRate: 0.01,
	})

	hashes := []types.Hash{
		{Type: types.HashTypeSHA256, Value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"},
		{Type: types.HashTypeSHA1, Value: "3395856ce81f2b7382dee72602f798b642f14140"},
		{Type: types.HashTypeMD5, Value: "44d88612fea8a8f36de82e1278abb02f"},
	}

	for _, h := range hashes {
		bf.Add(h)
	}

	// Save to file.
	err := bf.SaveToFile(path)
	if err != nil {
		t.Fatalf("SaveToFile() error: %v", err)
	}

	// Verify file exists.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("File should exist: %v", err)
	}

	// Load into new filter.
	loadedBf, err := engine.LoadBloomFilter(path)
	if err != nil {
		t.Fatalf("LoadBloomFilter() error: %v", err)
	}

	// Verify all hashes are present.
	for _, h := range hashes {
		if !loadedBf.Test(h) {
			t.Errorf("Loaded filter should contain hash %s:%s", h.Type, h.Value[:8])
		}
	}
}

func TestBloomFilter_Stats(t *testing.T) {
	t.Parallel()

	bf := engine.NewBloomFilter(engine.BloomConfig{
		ExpectedItems:   1000,
		FalsePositiveRate: 0.01,
	})

	// Add some hashes.
	for i := 0; i < 100; i++ {
		hash := types.Hash{
			Type:  types.HashTypeSHA256,
			Value: hashFromInt(i),
		}
		bf.Add(hash)
	}

	stats := bf.Stats()

	if stats.Capacity != 1000 {
		t.Errorf("Capacity = %d, want 1000", stats.Capacity)
	}
	if stats.FalsePositiveRate != 0.01 {
		t.Errorf("FalsePositiveRate = %f, want 0.01", stats.FalsePositiveRate)
	}
	if stats.BitSetSize == 0 {
		t.Error("BitSetSize should be > 0")
	}
}

func TestBloomFilter_Clear(t *testing.T) {
	t.Parallel()

	bf := engine.NewBloomFilter(engine.BloomConfig{
		ExpectedItems:   1000,
		FalsePositiveRate: 0.01,
	})

	hash := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	}

	bf.Add(hash)

	if !bf.Test(hash) {
		t.Fatal("Hash should be present before clear")
	}

	bf.Clear()

	if bf.Test(hash) {
		t.Error("Hash should not be present after clear")
	}
}
