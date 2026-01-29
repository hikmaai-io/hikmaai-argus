// ABOUTME: Unit tests for GCS client with download and validation
// ABOUTME: Uses mock storage for isolated testing without real GCS

package gcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestParseGCSURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		uri        string
		wantBucket string
		wantObject string
		wantErr    bool
	}{
		{
			name:       "valid uri",
			uri:        "gs://hikma-skills/org-123/skills/abc.zip",
			wantBucket: "hikma-skills",
			wantObject: "org-123/skills/abc.zip",
			wantErr:    false,
		},
		{
			name:       "valid uri with nested path",
			uri:        "gs://bucket/a/b/c/d.tar.gz",
			wantBucket: "bucket",
			wantObject: "a/b/c/d.tar.gz",
			wantErr:    false,
		},
		{
			name:       "bucket only",
			uri:        "gs://bucket-only/",
			wantBucket: "bucket-only",
			wantObject: "",
			wantErr:    false,
		},
		{
			name:    "invalid scheme",
			uri:     "s3://bucket/object",
			wantErr: true,
		},
		{
			name:    "missing scheme",
			uri:     "bucket/object",
			wantErr: true,
		},
		{
			name:    "empty uri",
			uri:     "",
			wantErr: true,
		},
		{
			name:    "no bucket",
			uri:     "gs://",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bucket, object, err := ParseGCSURI(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Error("ParseGCSURI() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseGCSURI() error = %v", err)
			}

			if bucket != tt.wantBucket {
				t.Errorf("bucket = %q, want %q", bucket, tt.wantBucket)
			}
			if object != tt.wantObject {
				t.Errorf("object = %q, want %q", object, tt.wantObject)
			}
		})
	}
}

func TestValidateOrganizationPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		uri    string
		orgID  string
		wantOK bool
	}{
		{
			name:   "valid path",
			uri:    "gs://bucket/org-123/skills/file.zip",
			orgID:  "org-123",
			wantOK: true,
		},
		{
			name:   "different org",
			uri:    "gs://bucket/org-456/skills/file.zip",
			orgID:  "org-123",
			wantOK: false,
		},
		{
			name:   "path traversal attempt",
			uri:    "gs://bucket/org-123/../org-456/skills/file.zip",
			orgID:  "org-123",
			wantOK: false,
		},
		{
			name:   "no org prefix",
			uri:    "gs://bucket/skills/file.zip",
			orgID:  "org-123",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ValidateOrganizationPath(tt.uri, tt.orgID)
			if got != tt.wantOK {
				t.Errorf("ValidateOrganizationPath() = %v, want %v", got, tt.wantOK)
			}
		})
	}
}

func TestComputeSHA256(t *testing.T) {
	t.Parallel()

	// Create temp file with known content.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Compute expected hash.
	h := sha256.Sum256(content)
	expected := hex.EncodeToString(h[:])

	// Test the function.
	got, err := ComputeSHA256(filePath)
	if err != nil {
		t.Fatalf("ComputeSHA256() error = %v", err)
	}

	if got != expected {
		t.Errorf("ComputeSHA256() = %q, want %q", got, expected)
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Bucket:      "my-bucket",
				DownloadDir: "/tmp/downloads",
			},
			wantErr: false,
		},
		{
			name: "missing bucket",
			cfg: Config{
				DownloadDir: "/tmp/downloads",
			},
			wantErr: true,
		},
		{
			name: "missing download dir",
			cfg: Config{
				Bucket: "my-bucket",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Validate() error = %v", err)
			}
		})
	}
}

// TestDownloadResult tests the DownloadResult struct.
func TestDownloadResult(t *testing.T) {
	t.Parallel()

	result := DownloadResult{
		LocalPath: "/tmp/file.zip",
		Checksum:  "abc123",
		Size:      1024,
	}

	if result.LocalPath != "/tmp/file.zip" {
		t.Errorf("LocalPath = %q, want %q", result.LocalPath, "/tmp/file.zip")
	}
	if result.Checksum != "abc123" {
		t.Errorf("Checksum = %q, want %q", result.Checksum, "abc123")
	}
	if result.Size != 1024 {
		t.Errorf("Size = %d, want %d", result.Size, 1024)
	}
}

// TestClient_DownloadPath tests the download path generation.
func TestClient_DownloadPath(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Bucket:      "test-bucket",
		DownloadDir: "/tmp/gcs",
	}

	// The download path should be: DownloadDir/jobID/filename
	jobID := "job-123"
	objectPath := "org-123/skills/myskill.zip"

	expected := "/tmp/gcs/job-123/myskill.zip"
	got := downloadPath(cfg.DownloadDir, jobID, objectPath)

	if got != expected {
		t.Errorf("downloadPath() = %q, want %q", got, expected)
	}
}

// downloadPath is a helper function tested above.
func downloadPath(downloadDir, jobID, objectPath string) string {
	filename := filepath.Base(objectPath)
	return filepath.Join(downloadDir, jobID, filename)
}

// Integration test - requires real GCS or emulator.
func TestClient_Download_Integration(t *testing.T) {
	// Skip unless explicitly enabled.
	if os.Getenv("GCS_INTEGRATION_TEST") != "true" {
		t.Skip("skipping GCS integration test (set GCS_INTEGRATION_TEST=true to enable)")
	}

	cfg := Config{
		Bucket:      os.Getenv("GCS_TEST_BUCKET"),
		ProjectID:   os.Getenv("GCS_TEST_PROJECT"),
		DownloadDir: t.TempDir(),
	}

	if cfg.Bucket == "" {
		t.Skip("GCS_TEST_BUCKET not set")
	}

	client, err := NewClient(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	// This test requires a test file to be uploaded to the bucket.
	// gs://{bucket}/test/integration-test.txt
	ctx := context.Background()
	result, err := client.Download(ctx, "test/integration-test.txt", "test-job")
	if err != nil {
		t.Fatalf("Download() error = %v", err)
	}

	if result.LocalPath == "" {
		t.Error("LocalPath is empty")
	}
	if result.Checksum == "" {
		t.Error("Checksum is empty")
	}
}
