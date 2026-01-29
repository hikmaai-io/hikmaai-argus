// ABOUTME: Tests for BadgerDB store wrapper
// ABOUTME: Covers signature storage, retrieval, batch operations, and statistics

package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestStore_PutAndGet(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)

	sig := &types.Signature{
		SHA256:        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		SHA1:          "3395856ce81f2b7382dee72602f798b642f14140",
		MD5:           "44d88612fea8a8f36de82e1278abb02f",
		DetectionName: "EICAR-Test-File",
		ThreatType:    types.ThreatTypeTestFile,
		Source:        "eicar",
		FirstSeen:     time.Now().UTC(),
	}

	ctx := context.Background()

	// Put signature.
	err := store.Put(ctx, sig)
	if err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	// Get by SHA256.
	hash := types.Hash{Type: types.HashTypeSHA256, Value: sig.SHA256}
	got, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("Get(SHA256) error: %v", err)
	}
	if got == nil {
		t.Fatal("Get(SHA256) returned nil")
	}
	if got.DetectionName != sig.DetectionName {
		t.Errorf("DetectionName = %v, want %v", got.DetectionName, sig.DetectionName)
	}

	// Get by SHA1.
	hash = types.Hash{Type: types.HashTypeSHA1, Value: sig.SHA1}
	got, err = store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("Get(SHA1) error: %v", err)
	}
	if got == nil {
		t.Fatal("Get(SHA1) returned nil")
	}

	// Get by MD5.
	hash = types.Hash{Type: types.HashTypeMD5, Value: sig.MD5}
	got, err = store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("Get(MD5) error: %v", err)
	}
	if got == nil {
		t.Fatal("Get(MD5) returned nil")
	}
}

func TestStore_GetNotFound(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	ctx := context.Background()

	hash := types.Hash{
		Type:  types.HashTypeSHA256,
		Value: "0000000000000000000000000000000000000000000000000000000000000000",
	}

	got, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got != nil {
		t.Errorf("Get() = %v, want nil for not found", got)
	}
}

func TestStore_BatchPut(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	ctx := context.Background()

	sigs := []*types.Signature{
		{
			SHA256:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			DetectionName: "Test.Malware.A",
			Source:        "test",
			FirstSeen:     time.Now().UTC(),
		},
		{
			SHA256:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			DetectionName: "Test.Malware.B",
			Source:        "test",
			FirstSeen:     time.Now().UTC(),
		},
		{
			SHA256:        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			DetectionName: "Test.Malware.C",
			Source:        "test",
			FirstSeen:     time.Now().UTC(),
		},
	}

	err := store.BatchPut(ctx, sigs)
	if err != nil {
		t.Fatalf("BatchPut() error: %v", err)
	}

	// Verify all signatures are stored.
	for _, sig := range sigs {
		hash := types.Hash{Type: types.HashTypeSHA256, Value: sig.SHA256}
		got, err := store.Get(ctx, hash)
		if err != nil {
			t.Errorf("Get(%s) error: %v", sig.SHA256[:8], err)
			continue
		}
		if got == nil {
			t.Errorf("Get(%s) returned nil", sig.SHA256[:8])
			continue
		}
		if got.DetectionName != sig.DetectionName {
			t.Errorf("DetectionName = %v, want %v", got.DetectionName, sig.DetectionName)
		}
	}
}

func TestStore_Delete(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	ctx := context.Background()

	sig := &types.Signature{
		SHA256:        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		DetectionName: "EICAR-Test-File",
		Source:        "eicar",
		FirstSeen:     time.Now().UTC(),
	}

	// Put signature.
	err := store.Put(ctx, sig)
	if err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	// Delete signature.
	hash := types.Hash{Type: types.HashTypeSHA256, Value: sig.SHA256}
	err = store.Delete(ctx, hash)
	if err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// Verify it's gone.
	got, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got != nil {
		t.Error("Get() should return nil after Delete()")
	}
}

func TestStore_Stats(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	ctx := context.Background()

	// Add some signatures.
	for i := 0; i < 5; i++ {
		sig := &types.Signature{
			SHA256:        hashFromInt(i),
			DetectionName: "Test.Malware",
			Source:        "test",
			FirstSeen:     time.Now().UTC(),
		}
		err := store.Put(ctx, sig)
		if err != nil {
			t.Fatalf("Put() error: %v", err)
		}
	}

	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error: %v", err)
	}

	if stats.SignatureCount < 5 {
		t.Errorf("SignatureCount = %d, want >= 5", stats.SignatureCount)
	}
}

func TestStore_IterateHashes(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	ctx := context.Background()

	// Add signatures.
	expected := make(map[string]bool)
	for i := 0; i < 10; i++ {
		h := hashFromInt(i)
		expected[h] = true
		sig := &types.Signature{
			SHA256:        h,
			DetectionName: "Test.Malware",
			Source:        "test",
			FirstSeen:     time.Now().UTC(),
		}
		err := store.Put(ctx, sig)
		if err != nil {
			t.Fatalf("Put() error: %v", err)
		}
	}

	// Iterate and collect hashes.
	seen := make(map[string]bool)
	err := store.IterateHashes(ctx, types.HashTypeSHA256, func(hash string) error {
		seen[hash] = true
		return nil
	})
	if err != nil {
		t.Fatalf("IterateHashes() error: %v", err)
	}

	// Verify all expected hashes were seen.
	for h := range expected {
		if !seen[h] {
			t.Errorf("hash %s not seen during iteration", h[:8])
		}
	}
}

// newTestStore creates a new in-memory store for testing.
func newTestStore(t *testing.T) *engine.Store {
	t.Helper()

	store, err := engine.NewStore(engine.StoreConfig{
		InMemory: true,
	})
	if err != nil {
		t.Fatalf("NewStore() error: %v", err)
	}

	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Store.Close() error: %v", err)
		}
	})

	return store
}

// hashFromInt generates a deterministic SHA256 hash string from an integer.
func hashFromInt(i int) string {
	base := "000000000000000000000000000000000000000000000000000000000000"
	suffix := []byte{'0' + byte(i/10), '0' + byte(i%10), 'a', 'b'}
	return base + string(suffix)
}
