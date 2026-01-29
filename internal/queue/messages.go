// ABOUTME: Message types for NATS request/reply communication
// ABOUTME: Defines ScanRequest and ScanResponse structures

package queue

import "time"

// ScanRequest is the message sent to request a hash scan.
type ScanRequest struct {
	// The hash to scan (SHA256, SHA1, or MD5).
	Hash string `json:"hash"`

	// Optional request ID for correlation.
	RequestID string `json:"request_id,omitempty"`

	// Optional metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ScanResponse is the response message for a scan request.
type ScanResponse struct {
	// Request ID for correlation.
	RequestID string `json:"request_id,omitempty"`

	// The hash that was scanned.
	Hash string `json:"hash"`

	// The detected hash type.
	HashType string `json:"hash_type"`

	// Scan status: "malware", "clean", "unknown", "error".
	Status string `json:"status"`

	// Detection name if malware was found.
	Detection string `json:"detection,omitempty"`

	// Threat type if malware was found.
	Threat string `json:"threat,omitempty"`

	// Severity if malware was found.
	Severity string `json:"severity,omitempty"`

	// Source of the signature.
	Source string `json:"source,omitempty"`

	// Error message if status is "error".
	Error string `json:"error,omitempty"`

	// Lookup time in milliseconds.
	LookupTimeMs float64 `json:"lookup_time_ms"`

	// Whether the bloom filter had a hit.
	BloomHit bool `json:"bloom_hit"`

	// Timestamp of the scan.
	ScannedAt time.Time `json:"scanned_at"`
}

// BatchScanRequest is the message for batch scan operations.
type BatchScanRequest struct {
	// List of hashes to scan.
	Hashes []string `json:"hashes"`

	// Optional request ID for correlation.
	RequestID string `json:"request_id,omitempty"`
}

// BatchScanResponse is the response for batch scan operations.
type BatchScanResponse struct {
	// Request ID for correlation.
	RequestID string `json:"request_id,omitempty"`

	// Individual scan results.
	Results []ScanResponse `json:"results"`

	// Total scan time in milliseconds.
	TotalTimeMs float64 `json:"total_time_ms"`
}
