// ABOUTME: Unit tests for Trivy Twirp HTTP client
// ABOUTME: Tests PutBlob, PutArtifact, and Scan endpoints with mocked HTTP server

package trivy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_PutBlob(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantErr    bool
		errContain string
	}{
		{
			name: "successful put blob",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.URL.Path != "/twirp/trivy.cache.v1.Cache/PutBlob" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("unexpected content-type: %s", ct)
				}

				body, _ := io.ReadAll(r.Body)
				var req TwirpPutBlobRequest
				if err := json.Unmarshal(body, &req); err != nil {
					t.Errorf("failed to parse request: %v", err)
				}
				if req.DiffID == "" {
					t.Error("expected diff_id in request")
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			},
			wantErr: false,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":"internal","msg":"database error"}`))
			},
			wantErr:    true,
			errContain: "internal",
		},
		{
			name: "twirp error response",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":"invalid_argument","msg":"invalid blob"}`))
			},
			wantErr:    true,
			errContain: "invalid_argument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := NewClient(ClientConfig{
				ServerURL: server.URL,
				Timeout:   5 * time.Second,
			})

			req := TwirpPutBlobRequest{
				DiffID: "sha256:abc123",
				BlobInfo: TwirpBlobInfo{
					SchemaVersion: 2,
					OS:            TwirpOSInfo{Family: "none"},
					Packages: []TwirpPackageInfo{
						{Name: "requests", Version: "2.25.0"},
					},
				},
			}

			err := client.PutBlob(context.Background(), req)
			if (err != nil) != tt.wantErr {
				t.Errorf("PutBlob() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errContain != "" && err != nil {
				if !contains(err.Error(), tt.errContain) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContain)
				}
			}
		})
	}
}

func TestClient_PutArtifact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantErr    bool
		errContain string
	}{
		{
			name: "successful put artifact",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.URL.Path != "/twirp/trivy.cache.v1.Cache/PutArtifact" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}

				body, _ := io.ReadAll(r.Body)
				var req TwirpPutArtifactRequest
				if err := json.Unmarshal(body, &req); err != nil {
					t.Errorf("failed to parse request: %v", err)
				}
				if req.ArtifactID == "" {
					t.Error("expected artifact_id in request")
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			},
			wantErr: false,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"code":"unavailable","msg":"service down"}`))
			},
			wantErr:    true,
			errContain: "unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := NewClient(ClientConfig{
				ServerURL: server.URL,
				Timeout:   5 * time.Second,
			})

			req := TwirpPutArtifactRequest{
				ArtifactID: "sha256:def456",
				ArtifactInfo: TwirpArtifactInfo{
					SchemaVersion: 1,
					Architecture:  "",
					Created:       time.Now(),
					OS:            TwirpOSInfo{Family: "none"},
				},
			}

			err := client.PutArtifact(context.Background(), req)
			if (err != nil) != tt.wantErr {
				t.Errorf("PutArtifact() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errContain != "" && err != nil {
				if !contains(err.Error(), tt.errContain) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContain)
				}
			}
		})
	}
}

func TestClient_Scan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantVulns  int
		wantErr    bool
		errContain string
	}{
		{
			name: "successful scan with vulnerabilities",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.URL.Path != "/twirp/trivy.scanner.v1.Scanner/Scan" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}

				body, _ := io.ReadAll(r.Body)
				var req TwirpScanRequest
				if err := json.Unmarshal(body, &req); err != nil {
					t.Errorf("failed to parse request: %v", err)
				}
				if len(req.BlobIDs) == 0 {
					t.Error("expected blob_ids in request")
				}

				resp := TwirpScanResponse{
					Results: []TwirpResult{
						{
							Target: "dependency-scan",
							Type:   "pip",
							Vulnerabilities: []TwirpVulnerability{
								{
									VulnerabilityID:  "CVE-2023-32681",
									PkgName:          "requests",
									InstalledVersion: "2.25.0",
									FixedVersion:     "2.31.0",
									Severity:         "HIGH",
									Title:            "Proxy-Auth header leak",
								},
								{
									VulnerabilityID:  "CVE-2023-99999",
									PkgName:          "urllib3",
									InstalledVersion: "1.26.0",
									FixedVersion:     "1.26.5",
									Severity:         "CRITICAL",
									Title:            "Request smuggling",
								},
							},
						},
					},
				}

				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantVulns: 2,
			wantErr:   false,
		},
		{
			name: "successful scan no vulnerabilities",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				resp := TwirpScanResponse{
					Results: []TwirpResult{
						{
							Target:          "dependency-scan",
							Type:            "pip",
							Vulnerabilities: nil,
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			},
			wantVulns: 0,
			wantErr:   false,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":"internal","msg":"scan failed"}`))
			},
			wantErr:    true,
			errContain: "internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := NewClient(ClientConfig{
				ServerURL: server.URL,
				Timeout:   5 * time.Second,
			})

			req := TwirpScanRequest{
				Target:     "dependency-scan",
				ArtifactID: "sha256:def456",
				BlobIDs:    []string{"sha256:abc123"},
				Options: TwirpScanOptions{
					Scanners: []string{"vuln"},
					PkgTypes: []string{"pip"},
				},
			}

			resp, err := client.Scan(context.Background(), req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Scan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errContain != "" && err != nil {
					if !contains(err.Error(), tt.errContain) {
						t.Errorf("error %q should contain %q", err.Error(), tt.errContain)
					}
				}
				return
			}

			totalVulns := 0
			for _, result := range resp.Results {
				totalVulns += len(result.Vulnerabilities)
			}
			if totalVulns != tt.wantVulns {
				t.Errorf("got %d vulnerabilities, want %d", totalVulns, tt.wantVulns)
			}
		})
	}
}

func TestClient_Timeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		ServerURL: server.URL,
		Timeout:   50 * time.Millisecond,
	})

	ctx := context.Background()
	req := TwirpPutBlobRequest{
		DiffID: "sha256:abc123",
		BlobInfo: TwirpBlobInfo{
			SchemaVersion: 2,
			OS:            TwirpOSInfo{Family: "none"},
		},
	}

	err := client.PutBlob(ctx, req)
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	req := TwirpPutBlobRequest{
		DiffID: "sha256:abc123",
		BlobInfo: TwirpBlobInfo{
			SchemaVersion: 2,
			OS:            TwirpOSInfo{Family: "none"},
		},
	}

	err := client.PutBlob(ctx, req)
	if err == nil {
		t.Error("expected context cancellation error, got nil")
	}
}

func TestClient_InvalidServerURL(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientConfig{
		ServerURL: "http://invalid.localhost.invalid:99999",
		Timeout:   1 * time.Second,
	})

	req := TwirpPutBlobRequest{
		DiffID: "sha256:abc123",
		BlobInfo: TwirpBlobInfo{
			SchemaVersion: 2,
			OS:            TwirpOSInfo{Family: "none"},
		},
	}

	err := client.PutBlob(context.Background(), req)
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}

func TestNewClient_Defaults(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientConfig{
		ServerURL: "http://localhost:4954",
	})

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// Test that default timeout is applied
	if client.timeout == 0 {
		t.Error("expected non-zero timeout")
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
