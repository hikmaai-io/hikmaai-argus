// ABOUTME: Integration tests for the complete lookup flow
// ABOUTME: End-to-end verification of EICAR detection

package engine_test

import (
	"context"
	"testing"

	"github.com/hikmaai-io/hikma-av/internal/engine"
	"github.com/hikmaai-io/hikma-av/internal/feeds"
	"github.com/hikmaai-io/hikma-av/internal/types"
)

func TestIntegration_EICARDetection(t *testing.T) {
	t.Parallel()

	// Create engine.
	eng, err := engine.NewEngine(engine.EngineConfig{
		StoreConfig: engine.StoreConfig{
			InMemory: true,
		},
		BloomConfig: engine.BloomConfig{
			ExpectedItems:     1000,
			FalsePositiveRate: 0.01,
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	defer eng.Close()

	ctx := context.Background()

	// Load EICAR signatures.
	eicarSigs := feeds.EICARSignatures()
	err = eng.BatchAddSignatures(ctx, eicarSigs)
	if err != nil {
		t.Fatalf("BatchAddSignatures() error: %v", err)
	}

	// Test detection by SHA256.
	hash, _ := types.ParseHash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
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

	// Test detection by SHA1.
	hash, _ = types.ParseHash("3395856ce81f2b7382dee72602f798b642f14140")
	result, err = eng.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup(SHA1) error: %v", err)
	}
	if result.Status != types.StatusMalware {
		t.Errorf("Lookup(SHA1) Status = %v, want %v", result.Status, types.StatusMalware)
	}

	// Test detection by MD5.
	hash, _ = types.ParseHash("44d88612fea8a8f36de82e1278abb02f")
	result, err = eng.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup(MD5) error: %v", err)
	}
	if result.Status != types.StatusMalware {
		t.Errorf("Lookup(MD5) Status = %v, want %v", result.Status, types.StatusMalware)
	}

	// Test clean hash.
	hash, _ = types.ParseHash("0000000000000000000000000000000000000000000000000000000000000000")
	result, err = eng.Lookup(ctx, hash)
	if err != nil {
		t.Fatalf("Lookup(clean) error: %v", err)
	}
	if result.Status != types.StatusUnknown {
		t.Errorf("Clean hash Status = %v, want %v", result.Status, types.StatusUnknown)
	}

	// Verify stats.
	stats, err := eng.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats() error: %v", err)
	}
	if stats.SignatureCount == 0 {
		t.Error("SignatureCount should be > 0")
	}
	if stats.MalwareDetected < 3 {
		t.Errorf("MalwareDetected = %d, want >= 3", stats.MalwareDetected)
	}
}

func TestIntegration_CSVFeedImport(t *testing.T) {
	t.Parallel()

	// Create engine.
	eng, err := engine.NewEngine(engine.EngineConfig{
		StoreConfig: engine.StoreConfig{
			InMemory: true,
		},
		BloomConfig: engine.BloomConfig{
			ExpectedItems:     1000,
			FalsePositiveRate: 0.01,
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}
	defer eng.Close()

	ctx := context.Background()

	// Create test signatures.
	sigs := []*types.Signature{
		{
			SHA256:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			DetectionName: "Test.Malware.A",
			ThreatType:    types.ThreatTypeTrojan,
			Severity:      types.SeverityHigh,
			Source:        "test",
		},
		{
			SHA256:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			DetectionName: "Test.Malware.B",
			ThreatType:    types.ThreatTypeRansomware,
			Severity:      types.SeverityCritical,
			Source:        "test",
		},
	}

	// Import signatures.
	err = eng.BatchAddSignatures(ctx, sigs)
	if err != nil {
		t.Fatalf("BatchAddSignatures() error: %v", err)
	}

	// Verify detection.
	for _, sig := range sigs {
		hash, _ := types.ParseHash(sig.SHA256)
		result, err := eng.Lookup(ctx, hash)
		if err != nil {
			t.Errorf("Lookup(%s) error: %v", sig.SHA256[:8], err)
			continue
		}
		if result.Status != types.StatusMalware {
			t.Errorf("Lookup(%s) Status = %v, want %v", sig.SHA256[:8], result.Status, types.StatusMalware)
		}
		if result.Signature == nil {
			t.Errorf("Lookup(%s) Signature is nil", sig.SHA256[:8])
			continue
		}
		if result.Signature.DetectionName != sig.DetectionName {
			t.Errorf("DetectionName = %v, want %v", result.Signature.DetectionName, sig.DetectionName)
		}
	}
}
