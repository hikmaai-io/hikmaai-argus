// ABOUTME: Hash type for representing file hashes (SHA256, SHA1, MD5)
// ABOUTME: Provides parsing, validation, and key generation for BadgerDB storage

package types

import (
	"fmt"
	"strings"
)

// HashType represents the type of hash algorithm.
type HashType int

const (
	// HashTypeUnknown represents an unknown or invalid hash type.
	HashTypeUnknown HashType = iota
	// HashTypeSHA256 represents a SHA-256 hash (64 hex characters).
	HashTypeSHA256
	// HashTypeSHA1 represents a SHA-1 hash (40 hex characters).
	HashTypeSHA1
	// HashTypeMD5 represents an MD5 hash (32 hex characters).
	HashTypeMD5
)

// Hash length constants.
const (
	SHA256Length = 64
	SHA1Length   = 40
	MD5Length    = 32
)

// String returns the string representation of the hash type.
func (ht HashType) String() string {
	switch ht {
	case HashTypeSHA256:
		return "sha256"
	case HashTypeSHA1:
		return "sha1"
	case HashTypeMD5:
		return "md5"
	default:
		return "unknown"
	}
}

// Hash represents a file hash with its type and value.
type Hash struct {
	Type  HashType `json:"type"`
	Value string   `json:"value"`
}

// ParseHash parses a hash string and returns a Hash with the detected type.
// It normalizes the hash to lowercase and trims whitespace.
func ParseHash(s string) (Hash, error) {
	s = strings.TrimSpace(s)

	if s == "" {
		return Hash{}, fmt.Errorf("empty hash")
	}

	// Normalize to lowercase.
	s = strings.ToLower(s)

	// Validate hex characters.
	for _, c := range s {
		if !isHexChar(c) {
			return Hash{}, fmt.Errorf("invalid hex characters in hash")
		}
	}

	// Detect hash type by length.
	var hashType HashType
	switch len(s) {
	case SHA256Length:
		hashType = HashTypeSHA256
	case SHA1Length:
		hashType = HashTypeSHA1
	case MD5Length:
		hashType = HashTypeMD5
	default:
		return Hash{}, fmt.Errorf("invalid hash length %d: must be %d (SHA256), %d (SHA1), or %d (MD5)",
			len(s), SHA256Length, SHA1Length, MD5Length)
	}

	return Hash{
		Type:  hashType,
		Value: s,
	}, nil
}

// Key returns the storage key for this hash (e.g., "sha256:abc123").
func (h Hash) Key() string {
	return h.Type.String() + ":" + h.Value
}

// IsValid returns true if the hash has a valid type and correct length.
func (h Hash) IsValid() bool {
	if h.Type == HashTypeUnknown || h.Value == "" {
		return false
	}

	expectedLen := 0
	switch h.Type {
	case HashTypeSHA256:
		expectedLen = SHA256Length
	case HashTypeSHA1:
		expectedLen = SHA1Length
	case HashTypeMD5:
		expectedLen = MD5Length
	default:
		return false
	}

	return len(h.Value) == expectedLen
}

// isHexChar returns true if the rune is a valid hexadecimal character.
func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
