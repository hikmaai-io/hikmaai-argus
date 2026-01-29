// ABOUTME: Tests for the Lookup Engine combining Bloom filter and BadgerDB
// ABOUTME: Covers lookup flow, EICAR detection, and rebuild operations

package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// EICAR test file hashes.
const (
	eicarSHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	eicarSHA1   = "3395856ce81f2b7382dee72602f798b642f14140"
	eicarMD5    = "44d88612fea8a8f36de82e1278abb02f"
)

func TestEngine_LookupMalware(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ctx := context.Background()

	// Add EICAR signature.
	sig := &types.Signature{
		SHA256:        eicarSHA256,
		SHA1:          eicarSHA1,
		MD5:           eicarMD5,
		DetectionName: "EICAR-Test-File",
		ThreatType:    types.ThreatTypeTestFile,
		Severity:      types.SeverityLow,
		Source:        "eicar",
		FirstSeen:     time.Now().UTC(),
	}

	err := eng.AddSignature(ctx, sig)
	if err != nil {
		t.Fatalf("AddSignature() error: %v", err)
	}

	// Lookup by SHA256.
	hash, _ := types.ParseHash(eicarSHA256)
	result, err := eng.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup(SHA256) error: %v", err)
	}

	if result.Status != types.StatusMalware {
		t.Errorf("Status = %v, want %v", result.Status, types.StatusMalware)
	}
	if result.Signature == nil {
		t.Fatal("Signature should not be nil")
	}
	if result.Signature.DetectionName != "EICAR-Test-File" {
		t.Errorf("DetectionName = %v, want EICAR-Test-File", result.Signature.DetectionName)
	}

	// Lookup by SHA1.
	hash, _ = types.ParseHash(eicarSHA1)
	result, err = eng.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup(SHA1) error: %v", err)
	}
	if result.Status != types.StatusMalware {
		t.Errorf("Lookup(SHA1) Status = %v, want %v", result.Status, types.StatusMalware)
	}

	// Lookup by MD5.
	hash, _ = types.ParseHash(eicarMD5)
	result, err = eng.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup(MD5) error: %v", err)
	}
	if result.Status != types.StatusMalware {
		t.Errorf("Lookup(MD5) Status = %v, want %v", result.Status, types.StatusMalware)
	}
}

func TestEngine_LookupClean(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ctx := context.Background()

	// Lookup unknown hash.
	hash, _ := types.ParseHash("0000000000000000000000000000000000000000000000000000000000000000")
	result, err := eng.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}

	// Unknown hash should return StatusUnknown.
	if result.Status != types.StatusUnknown {
		t.Errorf("Status = %v, want %v", result.Status, types.StatusUnknown)
	}
	if result.Signature != nil {
		t.Error("Signature should be nil for unknown hash")
	}
}

func TestEngine_BloomFilterRejection(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ctx := context.Background()

	// Add some signatures to populate the bloom filter.
	for i := 0; i < 100; i++ {
		sig := &types.Signature{
			SHA256:        hashFromInt(i),
			DetectionName: "Test.Malware",
			Source:        "test",
			FirstSeen:     time.Now().UTC(),
		}
		err := eng.AddSignature(ctx, sig)
		if err != nil {
			t.Fatalf("AddSignature() error: %v", err)
		}
	}

	// Lookup an unknown hash - should be rejected by bloom filter.
	hash, _ := types.ParseHash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	result, err := eng.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}

	// Bloom filter rejection should result in unknown status.
	if result.Status != types.StatusUnknown {
		t.Errorf("Status = %v, want %v", result.Status, types.StatusUnknown)
	}

	// BloomHit should be false (quick rejection).
	if result.BloomHit {
		t.Error("BloomHit should be false for rejected hash")
	}
}

func TestEngine_BatchAddSignatures(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ctx := context.Background()

	sigs := make([]*types.Signature, 50)
	for i := 0; i < 50; i++ {
		sigs[i] = &types.Signature{
			SHA256:        hashFromInt(i),
			DetectionName: "Test.Malware",
			Source:        "test",
			FirstSeen:     time.Now().UTC(),
		}
	}

	err := eng.BatchAddSignatures(ctx, sigs)
	if err != nil {
		t.Fatalf("BatchAddSignatures() error: %v", err)
	}

	// Verify all signatures are findable.
	for i := 0; i < 50; i++ {
		hash, _ := types.ParseHash(hashFromInt(i))
		result, err := eng.Lookup(ctx, hash)
		if err != nil {
			t.Errorf("Lookup(%d) error: %v", i, err)
			continue
		}
		if result.Status != types.StatusMalware {
			t.Errorf("Lookup(%d) Status = %v, want %v", i, result.Status, types.StatusMalware)
		}
	}
}

func TestEngine_RebuildBloomFilter(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ctx := context.Background()

	// Add signatures directly to store (simulating import).
	for i := 0; i < 20; i++ {
		sig := &types.Signature{
			SHA256:        hashFromInt(i),
			DetectionName: "Test.Malware",
			Source:        "test",
			FirstSeen:     time.Now().UTC(),
		}
		err := eng.AddSignature(ctx, sig)
		if err != nil {
			t.Fatalf("AddSignature() error: %v", err)
		}
	}

	// Rebuild bloom filter.
	err := eng.RebuildBloomFilter(ctx)
	if err != nil {
		t.Fatalf("RebuildBloomFilter() error: %v", err)
	}

	// Verify lookups still work.
	for i := 0; i < 20; i++ {
		hash, _ := types.ParseHash(hashFromInt(i))
		result, err := eng.Lookup(ctx, hash)
		if err != nil {
			t.Errorf("Lookup(%d) error: %v", i, err)
			continue
		}
		if result.Status != types.StatusMalware {
			t.Errorf("Lookup(%d) Status = %v, want %v", i, result.Status, types.StatusMalware)
		}
	}
}

func TestEngine_Stats(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ctx := context.Background()

	// Add some signatures.
	for i := 0; i < 10; i++ {
		sig := &types.Signature{
			SHA256:        hashFromInt(i),
			DetectionName: "Test.Malware",
			Source:        "test",
			FirstSeen:     time.Now().UTC(),
		}
		err := eng.AddSignature(ctx, sig)
		if err != nil {
			t.Fatalf("AddSignature() error: %v", err)
		}
	}

	stats, err := eng.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error: %v", err)
	}

	if stats.SignatureCount < 10 {
		t.Errorf("SignatureCount = %d, want >= 10", stats.SignatureCount)
	}
}

func TestEngine_LookupWithTracing(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ctx := context.Background()

	// Add EICAR signature.
	sig := &types.Signature{
		SHA256:        eicarSHA256,
		DetectionName: "EICAR-Test-File",
		Source:        "eicar",
		FirstSeen:     time.Now().UTC(),
	}

	err := eng.AddSignature(ctx, sig)
	if err != nil {
		t.Fatalf("AddSignature() error: %v", err)
	}

	// Lookup should include timing metadata.
	hash, _ := types.ParseHash(eicarSHA256)
	result, err := eng.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup() error: %v", err)
	}

	if result.LookupTimeMs <= 0 {
		t.Error("LookupTimeMs should be > 0")
	}
}

// newTestEngine creates a new in-memory engine for testing.
func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()

	cfg := engine.EngineConfig{
		StoreConfig: engine.StoreConfig{
			InMemory: true,
		},
		BloomConfig: engine.BloomConfig{
			ExpectedItems:     10000,
			FalsePositiveRate: 0.01,
		},
	}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	t.Cleanup(func() {
		if err := eng.Close(); err != nil {
			t.Errorf("Engine.Close() error: %v", err)
		}
	})

	return eng
}
