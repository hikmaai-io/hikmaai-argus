// ABOUTME: GCS client for downloading skill archives with checksum verification
// ABOUTME: Supports ADC authentication, emulator mode, and organization path validation

package gcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// Config holds GCS client configuration.
type Config struct {
	// Bucket is the GCS bucket name.
	Bucket string

	// ProjectID is the GCP project ID (optional for ADC).
	ProjectID string

	// CredentialsFile is the path to service account JSON (optional).
	// If empty, uses Application Default Credentials (ADC).
	CredentialsFile string

	// DownloadDir is the base directory for downloaded files.
	DownloadDir string

	// EmulatorHost is the GCS emulator host (e.g., "localhost:4443").
	// When set, the client uses HTTP directly instead of the Go SDK.
	// This works around googleapis/google-cloud-go#6139 where the SDK
	// uses path-style URLs that fake-gcs-server doesn't support.
	EmulatorHost string
}

// Validate checks that required fields are set.
func (c *Config) Validate() error {
	if c.Bucket == "" {
		return errors.New("bucket is required")
	}
	if c.DownloadDir == "" {
		return errors.New("download directory is required")
	}
	return nil
}

// DownloadResult contains information about a downloaded file.
type DownloadResult struct {
	// LocalPath is the full path to the downloaded file.
	LocalPath string

	// Checksum is the SHA256 hash of the downloaded file.
	Checksum string

	// Size is the file size in bytes.
	Size int64
}

// Client wraps the GCS storage client.
type Client struct {
	storageClient *storage.Client
	httpClient    *http.Client
	bucket        string
	downloadDir   string
	emulatorHost  string // Non-empty when using emulator mode
}

// NewClient creates a new GCS client.
// When STORAGE_EMULATOR_HOST is set or EmulatorHost is configured,
// the client uses HTTP directly to work around Go SDK limitations.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Check for emulator: explicit config takes precedence, then env var
	emulatorHost := cfg.EmulatorHost
	if emulatorHost == "" {
		emulatorHost = os.Getenv("STORAGE_EMULATOR_HOST")
	}

	// If using emulator, use HTTP client directly
	if emulatorHost != "" {
		return &Client{
			httpClient:   &http.Client{},
			bucket:       cfg.Bucket,
			downloadDir:  cfg.DownloadDir,
			emulatorHost: emulatorHost,
		}, nil
	}

	// Production mode: use Go SDK
	var opts []option.ClientOption
	if cfg.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
	}

	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating storage client: %w", err)
	}

	return &Client{
		storageClient: client,
		bucket:        cfg.Bucket,
		downloadDir:   cfg.DownloadDir,
	}, nil
}

// Close closes the GCS client.
func (c *Client) Close() error {
	if c.storageClient != nil {
		return c.storageClient.Close()
	}
	return nil
}

// IsEmulatorMode returns true if the client is configured for emulator mode.
func (c *Client) IsEmulatorMode() bool {
	return c.emulatorHost != ""
}

// Download downloads an object from GCS to the local filesystem.
// The file is saved to DownloadDir/jobID/filename.
func (c *Client) Download(ctx context.Context, objectPath, jobID string) (*DownloadResult, error) {
	// Create job-specific directory.
	jobDir := filepath.Join(c.downloadDir, jobID)
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating download directory %s: %w", jobDir, err)
	}

	// Determine local file path.
	filename := filepath.Base(objectPath)
	localPath := filepath.Join(jobDir, filename)

	// Use HTTP for emulator, SDK for production
	if c.emulatorHost != "" {
		return c.downloadViaHTTP(ctx, objectPath, localPath)
	}

	return c.downloadViaSDK(ctx, objectPath, localPath)
}

// downloadViaHTTP downloads an object using HTTP directly.
// This works around googleapis/google-cloud-go#6139 where the Go SDK
// uses path-style URLs that fake-gcs-server doesn't support for reads.
func (c *Client) downloadViaHTTP(ctx context.Context, objectPath, localPath string) (*DownloadResult, error) {
	// Build the JSON API URL that fake-gcs-server expects
	// Format: http://{host}/storage/v1/b/{bucket}/o/{object}?alt=media
	encodedObject := url.PathEscape(objectPath)
	downloadURL := fmt.Sprintf("http://%s/storage/v1/b/%s/o/%s?alt=media",
		c.emulatorHost, c.bucket, encodedObject)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request to %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading object %s/%s: HTTP %d", c.bucket, objectPath, resp.StatusCode)
	}

	// Create local file.
	file, err := os.Create(localPath)
	if err != nil {
		return nil, fmt.Errorf("creating local file %s: %w", localPath, err)
	}
	defer file.Close()

	// Download with hash computation.
	hasher := sha256.New()
	writer := io.MultiWriter(file, hasher)

	size, err := io.Copy(writer, resp.Body)
	if err != nil {
		_ = os.Remove(localPath)
		return nil, fmt.Errorf("downloading object: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	return &DownloadResult{
		LocalPath: localPath,
		Checksum:  checksum,
		Size:      size,
	}, nil
}

// downloadViaSDK downloads an object using the Go GCS SDK.
func (c *Client) downloadViaSDK(ctx context.Context, objectPath, localPath string) (*DownloadResult, error) {
	// Open GCS object.
	obj := c.storageClient.Bucket(c.bucket).Object(objectPath)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("opening object %s/%s: %w", c.bucket, objectPath, err)
	}
	defer reader.Close()

	// Create local file.
	file, err := os.Create(localPath)
	if err != nil {
		return nil, fmt.Errorf("creating local file %s: %w", localPath, err)
	}
	defer file.Close()

	// Download with hash computation.
	hasher := sha256.New()
	writer := io.MultiWriter(file, hasher)

	size, err := io.Copy(writer, reader)
	if err != nil {
		_ = os.Remove(localPath)
		return nil, fmt.Errorf("downloading object: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	return &DownloadResult{
		LocalPath: localPath,
		Checksum:  checksum,
		Size:      size,
	}, nil
}

// DownloadFromURI downloads an object using a gs:// URI.
func (c *Client) DownloadFromURI(ctx context.Context, uri, jobID string) (*DownloadResult, error) {
	bucket, objectPath, err := ParseGCSURI(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing URI: %w", err)
	}

	// Verify bucket matches.
	if bucket != c.bucket {
		return nil, fmt.Errorf("bucket mismatch: URI has %q, client configured for %q", bucket, c.bucket)
	}

	return c.Download(ctx, objectPath, jobID)
}

// ParseGCSURI parses a gs:// URI into bucket and object path.
func ParseGCSURI(uri string) (bucket, object string, err error) {
	if uri == "" {
		return "", "", errors.New("empty URI")
	}

	if !strings.HasPrefix(uri, "gs://") {
		return "", "", fmt.Errorf("invalid GCS URI: must start with gs://")
	}

	// Remove the gs:// prefix.
	path := strings.TrimPrefix(uri, "gs://")

	// Split into bucket and object.
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", "", errors.New("invalid GCS URI: missing bucket")
	}

	bucket = parts[0]
	if len(parts) > 1 {
		object = parts[1]
	}

	return bucket, object, nil
}

// ValidateOrganizationPath checks if the GCS URI belongs to the expected organization.
// Prevents path traversal attacks and cross-tenant access.
func ValidateOrganizationPath(uri, orgID string) bool {
	_, object, err := ParseGCSURI(uri)
	if err != nil {
		return false
	}

	// Clean the path to prevent traversal.
	cleanPath := filepath.Clean(object)
	if cleanPath != object {
		return false // Path contains traversal sequences.
	}

	// Check if path starts with org ID.
	expectedPrefix := orgID + "/"
	return strings.HasPrefix(object, expectedPrefix)
}

// ComputeSHA256 computes the SHA256 hash of a file.
func ComputeSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("computing hash: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyChecksum verifies that a file matches the expected SHA256 checksum.
func VerifyChecksum(filePath, expected string) error {
	actual, err := ComputeSHA256(filePath)
	if err != nil {
		return err
	}

	if actual != expected {
		return fmt.Errorf("checksum mismatch: got %s, expected %s", actual, expected)
	}

	return nil
}

// CleanupJobDir removes the job-specific download directory.
func (c *Client) CleanupJobDir(jobID string) error {
	jobDir := filepath.Join(c.downloadDir, jobID)
	if err := os.RemoveAll(jobDir); err != nil {
		return fmt.Errorf("removing directory %s: %w", jobDir, err)
	}
	return nil
}
