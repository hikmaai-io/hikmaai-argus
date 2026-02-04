// ABOUTME: Tests for signature feed updater (BadgerDB signatures)
// ABOUTME: Validates feed fetching, signature import, and engine integration

package dbupdater

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// mockSignatureFeed is a test implementation of the SignatureFeed interface.
type mockSignatureFeed struct {
	name       string
	signatures []*types.Signature
	shouldFail bool
	fetchCount atomic.Int32
}

func (m *mockSignatureFeed) Name() string {
	return m.name
}

func (m *mockSignatureFeed) Fetch(ctx context.Context) ([]*types.Signature, error) {
	m.fetchCount.Add(1)

	if m.shouldFail {
		return nil, errors.New("mock fetch failure")
	}

	return m.signatures, nil
}

// mockSignatureEngine is a test implementation of the SignatureEngine interface.
type mockSignatureEngine struct {
	addCount   atomic.Int32
	signatures []*types.Signature
	shouldFail bool
}

func (m *mockSignatureEngine) BatchAddSignatures(ctx context.Context, sigs []*types.Signature) error {
	if m.shouldFail {
		return errors.New("mock add failure")
	}

	m.addCount.Add(int32(len(sigs)))
	m.signatures = append(m.signatures, sigs...)
	return nil
}

func (m *mockSignatureEngine) Count() int64 {
	return int64(len(m.signatures))
}

func TestSignatureFeedUpdater_Name(t *testing.T) {
	t.Parallel()

	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{})

	if got := updater.Name(); got != "signatures" {
		t.Errorf("Name() = %q, want %q", got, "signatures")
	}
}

func TestSignatureFeedUpdater_RegisterFeed(t *testing.T) {
	t.Parallel()

	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{})

	feed := &mockSignatureFeed{name: "test"}
	updater.RegisterFeed(feed)

	if len(updater.feeds) != 1 {
		t.Errorf("feeds count = %d, want 1", len(updater.feeds))
	}
}

func TestSignatureFeedUpdater_Update_Success(t *testing.T) {
	t.Parallel()

	engine := &mockSignatureEngine{}
	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{
		Engine: engine,
	})

	feed := &mockSignatureFeed{
		name: "test",
		signatures: []*types.Signature{
			{SHA256: "abc123", DetectionName: "Test.Malware"},
			{SHA256: "def456", DetectionName: "Test.Trojan"},
		},
	}
	updater.RegisterFeed(feed)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := updater.Update(ctx)

	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if !result.Success {
		t.Error("Update() Success = false, want true")
	}
	if result.Downloaded != 2 {
		t.Errorf("Downloaded = %d, want 2", result.Downloaded)
	}
	if engine.addCount.Load() != 2 {
		t.Errorf("Engine add count = %d, want 2", engine.addCount.Load())
	}
}

func TestSignatureFeedUpdater_Update_MultipleFeeds(t *testing.T) {
	t.Parallel()

	engine := &mockSignatureEngine{}
	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{
		Engine: engine,
	})

	feed1 := &mockSignatureFeed{
		name: "feed1",
		signatures: []*types.Signature{
			{SHA256: "abc123"},
		},
	}
	feed2 := &mockSignatureFeed{
		name: "feed2",
		signatures: []*types.Signature{
			{SHA256: "def456"},
			{SHA256: "ghi789"},
		},
	}
	updater.RegisterFeed(feed1)
	updater.RegisterFeed(feed2)

	ctx := context.Background()
	result, err := updater.Update(ctx)

	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if result.Downloaded != 3 {
		t.Errorf("Downloaded = %d, want 3", result.Downloaded)
	}
}

func TestSignatureFeedUpdater_Update_FeedFailure(t *testing.T) {
	t.Parallel()

	engine := &mockSignatureEngine{}
	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{
		Engine: engine,
	})

	failingFeed := &mockSignatureFeed{
		name:       "failing",
		shouldFail: true,
	}
	successFeed := &mockSignatureFeed{
		name: "success",
		signatures: []*types.Signature{
			{SHA256: "abc123"},
		},
	}
	updater.RegisterFeed(failingFeed)
	updater.RegisterFeed(successFeed)

	ctx := context.Background()
	result, err := updater.Update(ctx)

	// Should still succeed partially.
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if result.Failed != 1 {
		t.Errorf("Failed = %d, want 1", result.Failed)
	}
	if result.Downloaded != 1 {
		t.Errorf("Downloaded = %d, want 1", result.Downloaded)
	}
}

func TestSignatureFeedUpdater_Update_EngineFailure(t *testing.T) {
	t.Parallel()

	engine := &mockSignatureEngine{shouldFail: true}
	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{
		Engine: engine,
	})

	feed := &mockSignatureFeed{
		name: "test",
		signatures: []*types.Signature{
			{SHA256: "abc123"},
		},
	}
	updater.RegisterFeed(feed)

	ctx := context.Background()
	result, err := updater.Update(ctx)

	if err == nil {
		t.Error("Update() should error on engine failure")
	}
	if result.Success {
		t.Error("Update() Success = true, want false")
	}
}

func TestSignatureFeedUpdater_Update_ContextCancellation(t *testing.T) {
	t.Parallel()

	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := updater.Update(ctx)

	if err == nil {
		t.Error("Update() should error on cancelled context")
	}
}

func TestSignatureFeedUpdater_CheckForUpdates(t *testing.T) {
	t.Parallel()

	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{})

	feed := &mockSignatureFeed{
		name: "test",
		signatures: []*types.Signature{
			{SHA256: "abc123"},
		},
	}
	updater.RegisterFeed(feed)

	ctx := context.Background()
	result, err := updater.CheckForUpdates(ctx)

	if err != nil {
		t.Fatalf("CheckForUpdates() error = %v", err)
	}
	// Always returns update available since we can't version check remote feeds.
	if !result.UpdateAvailable {
		t.Error("UpdateAvailable should be true")
	}
}

func TestSignatureFeedUpdater_GetVersionInfo(t *testing.T) {
	t.Parallel()

	engine := &mockSignatureEngine{}
	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{
		Engine: engine,
	})

	// Add some signatures to engine.
	engine.signatures = make([]*types.Signature, 100)

	info := updater.GetVersionInfo()

	if info.Version == 0 {
		t.Error("Version should be non-zero (based on signature count)")
	}
}

func TestSignatureFeedUpdater_IsReady(t *testing.T) {
	t.Parallel()

	// Without engine - not ready.
	updater1 := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{})
	if updater1.IsReady() {
		t.Error("IsReady() should be false without engine")
	}

	// With engine - ready.
	engine := &mockSignatureEngine{}
	updater2 := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{
		Engine: engine,
	})
	if !updater2.IsReady() {
		t.Error("IsReady() should be true with engine")
	}
}

func TestSignatureFeedUpdater_ImplementsUpdater(t *testing.T) {
	t.Parallel()

	var _ Updater = (*SignatureFeedUpdater)(nil)
}

func TestSignatureFeedUpdater_GetStats(t *testing.T) {
	t.Parallel()

	engine := &mockSignatureEngine{}
	updater := NewSignatureFeedUpdater(SignatureFeedUpdaterConfig{
		Engine: engine,
	})

	feed := &mockSignatureFeed{
		name: "test",
		signatures: []*types.Signature{
			{SHA256: "abc123"},
		},
	}
	updater.RegisterFeed(feed)

	ctx := context.Background()
	_, _ = updater.Update(ctx)

	stats := updater.GetStats()

	if stats.TotalSignatures != 1 {
		t.Errorf("TotalSignatures = %d, want 1", stats.TotalSignatures)
	}
	if stats.LastUpdateSignatures != 1 {
		t.Errorf("LastUpdateSignatures = %d, want 1", stats.LastUpdateSignatures)
	}
}
