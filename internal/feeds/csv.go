// ABOUTME: CSV feed parser for abuse.ch and similar feeds
// ABOUTME: Parses CSV files with configurable column mapping

package feeds

import (
	"bufio"
	"context"
	"io"
	"strings"
	"time"

	"github.com/hikmaai-io/hikma-av/internal/types"
)

// CSVConfig holds configuration for CSV parsing.
type CSVConfig struct {
	// Column indices (0-based, -1 means not present).
	SHA256Column    int
	SHA1Column      int
	MD5Column       int
	DetectionColumn int

	// Skip the first line (header).
	SkipHeader bool

	// Comment character (lines starting with this are skipped).
	CommentChar rune

	// Delimiter (default comma).
	Delimiter rune

	// Default values for signatures.
	DefaultThreatType  types.ThreatType
	DefaultSeverity    types.Severity
	DefaultDescription string
}

// CSVFeed parses CSV formatted signature feeds.
type CSVFeed struct {
	name   string
	config CSVConfig
}

// NewCSVFeed creates a new CSV feed parser.
func NewCSVFeed(name string, config CSVConfig) *CSVFeed {
	// Set defaults.
	if config.SHA1Column == 0 && config.SHA256Column != 0 {
		config.SHA1Column = -1
	}
	if config.MD5Column == 0 && config.SHA256Column != 0 {
		config.MD5Column = -1
	}
	if config.DetectionColumn == 0 && config.SHA256Column != 0 {
		config.DetectionColumn = -1
	}
	if config.Delimiter == 0 {
		config.Delimiter = ','
	}
	if config.DefaultThreatType == types.ThreatTypeUnknown {
		config.DefaultThreatType = types.ThreatTypeUnknown
	}

	return &CSVFeed{
		name:   name,
		config: config,
	}
}

// Name returns the name of the feed.
func (f *CSVFeed) Name() string {
	return f.name
}

// Parse parses signatures from a CSV reader.
func (f *CSVFeed) Parse(ctx context.Context, r io.Reader) ([]*types.Signature, error) {
	var sigs []*types.Signature

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		// Check for context cancellation.
		select {
		case <-ctx.Done():
			return sigs, ctx.Err()
		default:
		}

		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines.
		if line == "" {
			continue
		}

		// Skip comments.
		if f.config.CommentChar != 0 && len(line) > 0 && rune(line[0]) == f.config.CommentChar {
			continue
		}

		// Skip header.
		if f.config.SkipHeader && lineNum == 1 {
			continue
		}

		// Parse line.
		sig := f.parseLine(line)
		if sig != nil {
			sigs = append(sigs, sig)
		}
	}

	return sigs, scanner.Err()
}

// parseLine parses a single CSV line into a signature.
func (f *CSVFeed) parseLine(line string) *types.Signature {
	fields := strings.Split(line, string(f.config.Delimiter))

	// Extract SHA256 (required).
	sha256 := f.getField(fields, f.config.SHA256Column)
	if sha256 == "" || !isValidSHA256(sha256) {
		return nil
	}

	// Create signature.
	sig := &types.Signature{
		SHA256:      strings.ToLower(sha256),
		ThreatType:  f.config.DefaultThreatType,
		Severity:    f.config.DefaultSeverity,
		Source:      f.name,
		FirstSeen:   time.Now().UTC(),
		Description: f.config.DefaultDescription,
	}

	// Extract optional fields.
	if sha1 := f.getField(fields, f.config.SHA1Column); sha1 != "" && isValidSHA1(sha1) {
		sig.SHA1 = strings.ToLower(sha1)
	}
	if md5 := f.getField(fields, f.config.MD5Column); md5 != "" && isValidMD5(md5) {
		sig.MD5 = strings.ToLower(md5)
	}
	if detection := f.getField(fields, f.config.DetectionColumn); detection != "" {
		sig.DetectionName = detection
	} else {
		sig.DetectionName = f.name + ".Malware"
	}

	return sig
}

// getField returns the field at the given index, or empty string if invalid.
func (f *CSVFeed) getField(fields []string, index int) string {
	if index < 0 || index >= len(fields) {
		return ""
	}
	return strings.TrimSpace(fields[index])
}

// isValidSHA256 checks if a string is a valid SHA256 hash.
func isValidSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

// isValidSHA1 checks if a string is a valid SHA1 hash.
func isValidSHA1(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

// isValidMD5 checks if a string is a valid MD5 hash.
func isValidMD5(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

// isHexChar returns true if the rune is a valid hexadecimal character.
func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
