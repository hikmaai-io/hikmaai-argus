// ABOUTME: Twirp HTTP client for communicating with Trivy server
// ABOUTME: Implements PutBlob, PutArtifact, and Scan methods for vulnerability scanning

package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Twirp endpoint paths.
const (
	putBlobPath     = "/twirp/trivy.cache.v1.Cache/PutBlob"
	putArtifactPath = "/twirp/trivy.cache.v1.Cache/PutArtifact"
	scanPath        = "/twirp/trivy.scanner.v1.Scanner/Scan"
)

// Default client configuration values.
const (
	defaultTimeout = 2 * time.Minute
)

// ClientConfig holds configuration for the Trivy client.
type ClientConfig struct {
	// ServerURL is the base URL of the Trivy server (e.g., "http://trivy-server:4954").
	ServerURL string

	// Timeout for HTTP requests.
	Timeout time.Duration

	// HTTPClient is an optional custom HTTP client. If nil, a default client is created.
	HTTPClient *http.Client
}

// Client is a Twirp HTTP client for the Trivy server.
type Client struct {
	serverURL  string
	httpClient *http.Client
	timeout    time.Duration
}

// NewClient creates a new Trivy client with the given configuration.
func NewClient(cfg ClientConfig) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: timeout,
		}
	}

	return &Client{
		serverURL:  cfg.ServerURL,
		httpClient: httpClient,
		timeout:    timeout,
	}
}

// TwirpError represents an error response from the Twirp server.
type TwirpError struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

func (e TwirpError) Error() string {
	return fmt.Sprintf("twirp error: %s: %s", e.Code, e.Msg)
}

// PutBlob uploads blob information to the Trivy cache.
func (c *Client) PutBlob(ctx context.Context, req TwirpPutBlobRequest) error {
	_, err := c.doRequest(ctx, putBlobPath, req)
	return err
}

// PutArtifact uploads artifact information to the Trivy cache.
func (c *Client) PutArtifact(ctx context.Context, req TwirpPutArtifactRequest) error {
	_, err := c.doRequest(ctx, putArtifactPath, req)
	return err
}

// Scan performs a vulnerability scan and returns the results.
func (c *Client) Scan(ctx context.Context, req TwirpScanRequest) (*TwirpScanResponse, error) {
	body, err := c.doRequest(ctx, scanPath, req)
	if err != nil {
		return nil, err
	}

	var resp TwirpScanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to decode scan response: %w", err)
	}

	return &resp, nil
}

// doRequest performs an HTTP POST request to the given path with JSON body.
func (c *Client) doRequest(ctx context.Context, path string, reqBody interface{}) ([]byte, error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	url := c.serverURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var twirpErr TwirpError
		if err := json.Unmarshal(respBody, &twirpErr); err == nil && twirpErr.Code != "" {
			return nil, twirpErr
		}
		return nil, errors.New("server returned status " + resp.Status)
	}

	return respBody, nil
}

// ServerURL returns the configured server URL.
func (c *Client) ServerURL() string {
	return c.serverURL
}
