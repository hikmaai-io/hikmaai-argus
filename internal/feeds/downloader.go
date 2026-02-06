// ABOUTME: HTTP downloader for fetching feed data from remote URLs
// ABOUTME: Supports configurable timeouts and user-agent

package feeds

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DownloaderConfig holds configuration for the HTTP downloader.
type DownloaderConfig struct {
	// Timeout for HTTP requests.
	Timeout time.Duration

	// UserAgent for HTTP requests.
	UserAgent string

	// MaxSize limits the maximum download size in bytes (0 = unlimited).
	MaxSize int64
}

// DefaultDownloaderConfig returns sensible default configuration.
func DefaultDownloaderConfig() DownloaderConfig {
	return DownloaderConfig{
		Timeout:   5 * time.Minute,
		UserAgent: "clamav/1.0.0",
		MaxSize:   500 * 1024 * 1024, // 500MB max
	}
}

// Downloader handles HTTP downloads for feed data.
type Downloader struct {
	client *http.Client
	config DownloaderConfig
}

// NewDownloader creates a new HTTP downloader.
// If config is nil, default configuration is used.
func NewDownloader(config *DownloaderConfig) *Downloader {
	cfg := DefaultDownloaderConfig()
	if config != nil {
		cfg = *config
	}

	return &Downloader{
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		config: cfg,
	}
}

// Download fetches data from the given URL.
func (d *Downloader) Download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("User-Agent", d.config.UserAgent)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if d.config.MaxSize > 0 {
		reader = io.LimitReader(resp.Body, d.config.MaxSize)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return data, nil
}
