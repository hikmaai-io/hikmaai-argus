// ABOUTME: Tests for the GCS download size cap (disk-exhaustion protection)
// ABOUTME: Uses an httptest server in emulator mode to serve oversized payloads

package gcs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDownload_SizeCapExceeded(t *testing.T) {
	t.Parallel()

	// Serve a 1MB body.
	body := strings.Repeat("A", 1024*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	client, err := NewClient(context.Background(), Config{
		Bucket:          "test-bucket",
		DownloadDir:     t.TempDir(),
		EmulatorHost:    host,
		MaxDownloadSize: 1024, // 1KB cap, well below the 1MB body
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.Download(context.Background(), "org/file.bin", "job-1")
	if err == nil {
		t.Fatal("expected size limit error, got nil")
	}
	if !strings.Contains(err.Error(), "size limit") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}

func TestDownload_WithinSizeCap(t *testing.T) {
	t.Parallel()

	body := "small payload"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	client, err := NewClient(context.Background(), Config{
		Bucket:          "test-bucket",
		DownloadDir:     t.TempDir(),
		EmulatorHost:    host,
		MaxDownloadSize: 1024,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	res, err := client.Download(context.Background(), "org/file.bin", "job-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Size != int64(len(body)) {
		t.Errorf("expected size %d, got %d", len(body), res.Size)
	}
}
