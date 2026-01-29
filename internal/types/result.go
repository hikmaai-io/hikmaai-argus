// ABOUTME: Result type representing scan results from hash lookups
// ABOUTME: Contains status (clean/malware/unknown/error) and optional signature

package types

import (
	"time"
)

// Status represents the result status of a scan.
type Status int

const (
	// StatusUnknown indicates the hash was not found in the database.
	StatusUnknown Status = iota
	// StatusClean indicates the hash was checked and found to be clean.
	StatusClean
	// StatusMalware indicates the hash matches a known malware signature.
	StatusMalware
	// StatusError indicates an error occurred during the scan.
	StatusError
)

// String returns the string representation of the status.
func (s Status) String() string {
	switch s {
	case StatusClean:
		return "clean"
	case StatusMalware:
		return "malware"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// IsMalicious returns true if the status indicates a malicious file.
func (s Status) IsMalicious() bool {
	return s == StatusMalware
}

// Result represents the result of a hash scan.
type Result struct {
	// The hash that was scanned.
	Hash Hash `json:"hash"`

	// The scan result status.
	Status Status `json:"status"`

	// The matching signature if status is StatusMalware.
	Signature *Signature `json:"signature,omitempty"`

	// Error message if status is StatusError.
	Error string `json:"error,omitempty"`

	// Timestamp when the scan was performed.
	ScannedAt time.Time `json:"scanned_at"`

	// Lookup metadata.
	LookupTimeMs float64 `json:"lookup_time_ms,omitempty"`
	CacheHit     bool    `json:"cache_hit,omitempty"`
	BloomHit     bool    `json:"bloom_hit,omitempty"`
}

// NewCleanResult creates a new Result with StatusClean.
func NewCleanResult(hash Hash) Result {
	return Result{
		Hash:      hash,
		Status:    StatusClean,
		ScannedAt: time.Now().UTC(),
	}
}

// NewMalwareResult creates a new Result with StatusMalware and the matching signature.
func NewMalwareResult(hash Hash, sig *Signature) Result {
	return Result{
		Hash:      hash,
		Status:    StatusMalware,
		Signature: sig,
		ScannedAt: time.Now().UTC(),
	}
}

// NewUnknownResult creates a new Result with StatusUnknown.
func NewUnknownResult(hash Hash) Result {
	return Result{
		Hash:      hash,
		Status:    StatusUnknown,
		ScannedAt: time.Now().UTC(),
	}
}

// NewErrorResult creates a new Result with StatusError and an error message.
func NewErrorResult(hash Hash, errMsg string) Result {
	return Result{
		Hash:      hash,
		Status:    StatusError,
		Error:     errMsg,
		ScannedAt: time.Now().UTC(),
	}
}

// IsMalicious returns true if this result indicates a malicious file.
func (r Result) IsMalicious() bool {
	return r.Status.IsMalicious()
}

// WithLookupTime sets the lookup duration and returns the result for chaining.
func (r Result) WithLookupTime(ms float64) Result {
	r.LookupTimeMs = ms
	return r
}

// WithCacheHit sets the cache hit flag and returns the result for chaining.
func (r Result) WithCacheHit(hit bool) Result {
	r.CacheHit = hit
	return r
}

// WithBloomHit sets the bloom filter hit flag and returns the result for chaining.
func (r Result) WithBloomHit(hit bool) Result {
	r.BloomHit = hit
	return r
}
