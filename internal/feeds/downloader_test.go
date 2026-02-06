// ABOUTME: Tests for the HTTP downloader for feed fetching
// ABOUTME: Validates download functionality with test server

package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDownloader_Download(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantContent string
		wantErr     bool
	}{
		{
			name: "successful download",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("test content"))
			},
			wantContent: "test content",
			wantErr:     false,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantContent: "",
			wantErr:     true,
		},
		{
			name: "not found",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantContent: "",
			wantErr:     true,
		},
		{
			name: "forbidden",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			wantContent: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			d := NewDownloader(nil)
			data, err := d.Download(context.Background(), server.URL)

			if (err != nil) != tt.wantErr {
				t.Errorf("Download() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(data) != tt.wantContent {
				t.Errorf("Download() = %q, want %q", string(data), tt.wantContent)
			}
		})
	}
}

func TestDownloader_ContextCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Simulate slow response
		select {}
	}))
	defer server.Close()

	d := NewDownloader(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := d.Download(ctx, server.URL)
	if err == nil {
		t.Error("Download() expected error for cancelled context")
	}
}
