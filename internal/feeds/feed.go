// ABOUTME: Feed interface for signature sources
// ABOUTME: Defines the contract for feed parsers and loaders

package feeds

import (
	"context"
	"io"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// Feed represents a signature feed source.
type Feed interface {
	// Name returns the name of the feed.
	Name() string

	// Parse parses signatures from a reader.
	Parse(ctx context.Context, r io.Reader) ([]*types.Signature, error)
}

// FeedStats contains statistics about a parsed feed.
type FeedStats struct {
	// Name of the feed.
	Name string

	// Number of signatures parsed.
	SignatureCount int

	// Number of parse errors.
	ErrorCount int

	// Version information if available.
	Version string
}

// FeedResult contains the result of a feed parse operation.
type FeedResult struct {
	Signatures []*types.Signature
	Stats      FeedStats
	Errors     []error
}
