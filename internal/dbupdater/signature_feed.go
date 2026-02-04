// ABOUTME: Signature feed updater for BadgerDB periodic signature imports
// ABOUTME: Implements Updater interface, fetches from registered feeds, stores in engine

package dbupdater

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// SignatureFeed represents a source of malware signatures.
type SignatureFeed interface {
	// Name returns the feed identifier.
	Name() string

	// Fetch retrieves signatures from the feed.
	Fetch(ctx context.Context) ([]*types.Signature, error)
}

// SignatureEngine stores signatures in the database.
type SignatureEngine interface {
	// BatchAddSignatures adds multiple signatures to the database.
	BatchAddSignatures(ctx context.Context, sigs []*types.Signature) error

	// Count returns the total number of signatures.
	Count() int64
}

// SignatureFeedUpdaterConfig configures the signature feed updater.
type SignatureFeedUpdaterConfig struct {
	// Engine is the signature storage engine.
	Engine SignatureEngine
}

// SignatureFeedStats contains statistics about signature updates.
type SignatureFeedStats struct {
	// TotalSignatures is the current count in the database.
	TotalSignatures int64

	// LastUpdateSignatures is the count from the last update.
	LastUpdateSignatures int64

	// LastUpdateTime is when the last update occurred.
	LastUpdateTime time.Time

	// FeedStats contains per-feed statistics.
	FeedStats map[string]*FeedStat
}

// FeedStat contains statistics for a single feed.
type FeedStat struct {
	Name           string
	LastFetchCount int64
	LastFetchTime  time.Time
	LastError      string
}

// SignatureFeedUpdater manages periodic signature imports from feeds.
type SignatureFeedUpdater struct {
	mu     sync.RWMutex
	config SignatureFeedUpdaterConfig
	feeds  []SignatureFeed

	// Statistics.
	lastUpdateTime       time.Time
	lastUpdateSignatures int64
	feedStats            map[string]*FeedStat
}

// NewSignatureFeedUpdater creates a new signature feed updater.
func NewSignatureFeedUpdater(config SignatureFeedUpdaterConfig) *SignatureFeedUpdater {
	return &SignatureFeedUpdater{
		config:    config,
		feeds:     make([]SignatureFeed, 0),
		feedStats: make(map[string]*FeedStat),
	}
}

// Name returns the updater name.
func (u *SignatureFeedUpdater) Name() string {
	return "signatures"
}

// RegisterFeed adds a signature feed to the updater.
func (u *SignatureFeedUpdater) RegisterFeed(feed SignatureFeed) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.feeds = append(u.feeds, feed)
	u.feedStats[feed.Name()] = &FeedStat{Name: feed.Name()}
}

// Update fetches signatures from all registered feeds and stores them.
func (u *SignatureFeedUpdater) Update(ctx context.Context) (*UpdateResult, error) {
	// Check context first.
	select {
	case <-ctx.Done():
		return &UpdateResult{Success: false}, ctx.Err()
	default:
	}

	u.mu.RLock()
	feeds := make([]SignatureFeed, len(u.feeds))
	copy(feeds, u.feeds)
	engine := u.config.Engine
	u.mu.RUnlock()

	result := &UpdateResult{
		Success:    true,
		Downloaded: 0,
		Failed:     0,
	}

	var totalSignatures []*types.Signature

	// Fetch from all feeds.
	for _, feed := range feeds {
		select {
		case <-ctx.Done():
			return &UpdateResult{Success: false}, ctx.Err()
		default:
		}

		sigs, err := feed.Fetch(ctx)

		u.mu.Lock()
		stat := u.feedStats[feed.Name()]
		stat.LastFetchTime = time.Now()
		if err != nil {
			stat.LastError = err.Error()
			result.Failed++
			u.mu.Unlock()
			continue
		}
		stat.LastFetchCount = int64(len(sigs))
		stat.LastError = ""
		u.mu.Unlock()

		totalSignatures = append(totalSignatures, sigs...)
		result.Downloaded += len(sigs)
	}

	// Add to engine if we have signatures.
	if len(totalSignatures) > 0 && engine != nil {
		if err := engine.BatchAddSignatures(ctx, totalSignatures); err != nil {
			return &UpdateResult{
				Success:    false,
				Downloaded: result.Downloaded,
				Failed:     result.Failed,
			}, fmt.Errorf("failed to add signatures to engine: %w", err)
		}
	}

	// Update statistics.
	u.mu.Lock()
	u.lastUpdateTime = time.Now()
	u.lastUpdateSignatures = int64(result.Downloaded)
	u.mu.Unlock()

	return result, nil
}

// CheckForUpdates checks if updates are available.
// For signature feeds, we always return true since feeds are dynamic.
func (u *SignatureFeedUpdater) CheckForUpdates(ctx context.Context) (*CheckResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	u.mu.RLock()
	hasFeeds := len(u.feeds) > 0
	u.mu.RUnlock()

	return &CheckResult{
		UpdateAvailable: hasFeeds,
	}, nil
}

// GetVersionInfo returns version information based on signature count.
func (u *SignatureFeedUpdater) GetVersionInfo() VersionInfo {
	u.mu.RLock()
	defer u.mu.RUnlock()

	var count int64
	if u.config.Engine != nil {
		count = u.config.Engine.Count()
	}

	return VersionInfo{
		Version:   int(count),
		BuildTime: u.lastUpdateTime,
	}
}

// IsReady returns true if the engine is configured.
func (u *SignatureFeedUpdater) IsReady() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.config.Engine != nil
}

// GetStats returns statistics about signature updates.
func (u *SignatureFeedUpdater) GetStats() *SignatureFeedStats {
	u.mu.RLock()
	defer u.mu.RUnlock()

	var totalSigs int64
	if u.config.Engine != nil {
		totalSigs = u.config.Engine.Count()
	}

	feedStats := make(map[string]*FeedStat, len(u.feedStats))
	for name, stat := range u.feedStats {
		cp := *stat
		feedStats[name] = &cp
	}

	return &SignatureFeedStats{
		TotalSignatures:      totalSigs,
		LastUpdateSignatures: u.lastUpdateSignatures,
		LastUpdateTime:       u.lastUpdateTime,
		FeedStats:            feedStats,
	}
}

// Ensure SignatureFeedUpdater implements Updater interface.
var _ Updater = (*SignatureFeedUpdater)(nil)
