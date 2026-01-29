// ABOUTME: abuse.ch malware feeds (MalwareBazaar, ThreatFox, URLhaus)
// ABOUTME: Downloads and parses hash lists from abuse.ch services

package feeds

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// abuse.ch feed URLs.
const (
	MalwareBazaarDefaultURL = "https://bazaar.abuse.ch/export/txt/sha256/full/"
	ThreatFoxDefaultURL     = "https://threatfox.abuse.ch/export/csv/full/"
	URLhausDefaultURL       = "https://urlhaus.abuse.ch/downloads/csv/"
)

// MalwareBazaarFeed downloads and parses SHA256 hashes from MalwareBazaar.
type MalwareBazaarFeed struct {
	url        string
	downloader *Downloader
}

// NewMalwareBazaarFeed creates a new MalwareBazaar feed parser.
func NewMalwareBazaarFeed() *MalwareBazaarFeed {
	return &MalwareBazaarFeed{
		url:        MalwareBazaarDefaultURL,
		downloader: NewDownloader(nil),
	}
}

// Name returns the name of the feed.
func (f *MalwareBazaarFeed) Name() string {
	return "malwarebazaar"
}

// SetURL overrides the default URL (useful for testing).
func (f *MalwareBazaarFeed) SetURL(url string) {
	f.url = url
}

// Fetch downloads and parses the MalwareBazaar hash list.
func (f *MalwareBazaarFeed) Fetch(ctx context.Context) ([]*types.Signature, error) {
	data, err := f.downloader.Download(ctx, f.url)
	if err != nil {
		return nil, fmt.Errorf("downloading malwarebazaar feed: %w", err)
	}

	return f.ParseData(ctx, data)
}

// ParseData parses the raw MalwareBazaar data (handles ZIP compression).
func (f *MalwareBazaarFeed) ParseData(ctx context.Context, data []byte) ([]*types.Signature, error) {
	// Try to detect and decompress if ZIP.
	content, err := decompressIfNeeded(data)
	if err != nil {
		return nil, fmt.Errorf("decompressing data: %w", err)
	}

	return f.parseHashList(ctx, content)
}

// parseHashList parses a plain text hash list (one SHA256 per line).
func (f *MalwareBazaarFeed) parseHashList(ctx context.Context, data []byte) ([]*types.Signature, error) {
	var sigs []*types.Signature

	scanner := bufio.NewScanner(bytes.NewReader(data))
	now := time.Now().UTC()

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return sigs, ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate SHA256 format.
		if !isValidSHA256(line) {
			continue
		}

		sig := &types.Signature{
			SHA256:        strings.ToLower(line),
			DetectionName: "Malware.Generic",
			ThreatType:    types.ThreatTypeMalware,
			Severity:      types.SeverityHigh,
			Source:        f.Name(),
			FirstSeen:     now,
			Description:   "Known malware hash from MalwareBazaar",
		}

		sigs = append(sigs, sig)
	}

	if err := scanner.Err(); err != nil {
		return sigs, fmt.Errorf("scanning data: %w", err)
	}

	return sigs, nil
}

// ThreatFoxFeed downloads and parses IOCs from ThreatFox.
type ThreatFoxFeed struct {
	url        string
	downloader *Downloader
}

// NewThreatFoxFeed creates a new ThreatFox feed parser.
func NewThreatFoxFeed() *ThreatFoxFeed {
	return &ThreatFoxFeed{
		url:        ThreatFoxDefaultURL,
		downloader: NewDownloader(nil),
	}
}

// Name returns the name of the feed.
func (f *ThreatFoxFeed) Name() string {
	return "threatfox"
}

// SetURL overrides the default URL (useful for testing).
func (f *ThreatFoxFeed) SetURL(url string) {
	f.url = url
}

// Fetch downloads and parses the ThreatFox IOC list.
func (f *ThreatFoxFeed) Fetch(ctx context.Context) ([]*types.Signature, error) {
	data, err := f.downloader.Download(ctx, f.url)
	if err != nil {
		return nil, fmt.Errorf("downloading threatfox feed: %w", err)
	}

	return f.ParseData(ctx, data)
}

// ParseData parses the raw ThreatFox CSV data.
func (f *ThreatFoxFeed) ParseData(ctx context.Context, data []byte) ([]*types.Signature, error) {
	// Try to decompress if needed.
	content, err := decompressIfNeeded(data)
	if err != nil {
		return nil, fmt.Errorf("decompressing data: %w", err)
	}

	return f.parseCSV(ctx, content)
}

// parseCSV parses ThreatFox CSV format.
// Format: first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen_utc,confidence_level,reference,tags,anonymous,reporter
func (f *ThreatFoxFeed) parseCSV(ctx context.Context, data []byte) ([]*types.Signature, error) {
	var sigs []*types.Signature

	reader := csv.NewReader(bytes.NewReader(data))
	reader.Comment = '#'
	reader.FieldsPerRecord = -1 // Allow variable fields.

	now := time.Now().UTC()
	headerSkipped := false

	for {
		select {
		case <-ctx.Done():
			return sigs, ctx.Err()
		default:
		}

		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip malformed lines.
		}

		// Skip header.
		if !headerSkipped {
			headerSkipped = true
			if len(record) > 0 && strings.HasPrefix(record[0], "first_seen") {
				continue
			}
		}

		// Need at least: first_seen, ioc_id, ioc_value, ioc_type.
		if len(record) < 4 {
			continue
		}

		iocValue := strings.TrimSpace(record[2])
		iocType := strings.TrimSpace(record[3])

		// Only process hash types (md5_hash, sha1_hash, sha256_hash).
		var sig *types.Signature
		switch strings.ToLower(iocType) {
		case "sha256_hash":
			if isValidSHA256(iocValue) {
				sig = &types.Signature{
					SHA256: strings.ToLower(iocValue),
				}
			}
		case "sha1_hash":
			if isValidSHA1(iocValue) {
				sig = &types.Signature{
					SHA1: strings.ToLower(iocValue),
				}
			}
		case "md5_hash":
			if isValidMD5(iocValue) {
				sig = &types.Signature{
					MD5: strings.ToLower(iocValue),
				}
			}
		default:
			continue // Skip non-hash IOCs (URLs, IPs, domains).
		}

		if sig == nil {
			continue
		}

		// Get threat type if available.
		threatType := ""
		if len(record) > 4 {
			threatType = strings.TrimSpace(record[4])
		}

		// Get malware name if available.
		malwareName := "ThreatFox.Malware"
		if len(record) > 7 && record[7] != "" {
			malwareName = "ThreatFox." + strings.TrimSpace(record[7])
		}

		sig.DetectionName = malwareName
		sig.ThreatType = mapThreatType(threatType)
		sig.Severity = types.SeverityHigh
		sig.Source = f.Name()
		sig.FirstSeen = now
		sig.Description = fmt.Sprintf("ThreatFox IOC: %s", threatType)

		sigs = append(sigs, sig)
	}

	return sigs, nil
}

// URLhausFeed downloads and parses malicious URLs from URLhaus.
// Note: URLhaus primarily provides URLs, not file hashes.
type URLhausFeed struct {
	url        string
	downloader *Downloader
}

// NewURLhausFeed creates a new URLhaus feed parser.
func NewURLhausFeed() *URLhausFeed {
	return &URLhausFeed{
		url:        URLhausDefaultURL,
		downloader: NewDownloader(nil),
	}
}

// Name returns the name of the feed.
func (f *URLhausFeed) Name() string {
	return "urlhaus"
}

// SetURL overrides the default URL (useful for testing).
func (f *URLhausFeed) SetURL(url string) {
	f.url = url
}

// Fetch downloads and parses the URLhaus data.
// Note: URLhaus primarily contains URLs, not hashes. This extracts any payload hashes if present.
func (f *URLhausFeed) Fetch(ctx context.Context) ([]*types.Signature, error) {
	data, err := f.downloader.Download(ctx, f.url)
	if err != nil {
		return nil, fmt.Errorf("downloading urlhaus feed: %w", err)
	}

	return f.ParseData(ctx, data)
}

// ParseData parses the raw URLhaus CSV data.
// Format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
func (f *URLhausFeed) ParseData(ctx context.Context, data []byte) ([]*types.Signature, error) {
	// URLhaus CSV primarily contains URLs, not file hashes.
	// We parse it but extract minimal hash data if available.
	// For hash-based detection, MalwareBazaar is the better source.

	content, err := decompressIfNeeded(data)
	if err != nil {
		return nil, fmt.Errorf("decompressing data: %w", err)
	}

	// URLhaus CSV doesn't contain direct hashes in the main export.
	// Return empty for now; the payload hashes require a different API endpoint.
	_ = content
	return []*types.Signature{}, nil
}

// AbusechFeed is an alias for MalwareBazaarFeed for backward compatibility.
type AbusechFeed = MalwareBazaarFeed

// NewAbusechFeed creates a new abuse.ch (MalwareBazaar) feed parser.
func NewAbusechFeed() *AbusechFeed {
	return NewMalwareBazaarFeed()
}

// decompressIfNeeded detects and decompresses ZIP or GZIP data.
func decompressIfNeeded(data []byte) ([]byte, error) {
	// Check for ZIP magic bytes (PK).
	if len(data) >= 4 && data[0] == 'P' && data[1] == 'K' {
		return decompressZIP(data)
	}

	// Check for GZIP magic bytes.
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return decompressGZIP(data)
	}

	// Not compressed, return as-is.
	return data, nil
}

// decompressZIP extracts the first file from a ZIP archive.
func decompressZIP(data []byte) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}

	if len(reader.File) == 0 {
		return nil, fmt.Errorf("zip archive is empty")
	}

	// Extract first file.
	f := reader.File[0]
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("opening zip file %s: %w", f.Name, err)
	}
	defer rc.Close()

	// Limit size to prevent zip bombs.
	const maxSize = 500 * 1024 * 1024 // 500MB
	limitedReader := io.LimitReader(rc, maxSize)

	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading zip file %s: %w", f.Name, err)
	}

	return content, nil
}

// decompressGZIP decompresses GZIP data.
func decompressGZIP(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("opening gzip: %w", err)
	}
	defer reader.Close()

	// Limit size.
	const maxSize = 500 * 1024 * 1024 // 500MB
	limitedReader := io.LimitReader(reader, maxSize)

	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading gzip: %w", err)
	}

	return content, nil
}

// mapThreatType maps ThreatFox threat types to our ThreatType.
func mapThreatType(threatType string) types.ThreatType {
	switch strings.ToLower(threatType) {
	case "botnet_cc", "botnet":
		return types.ThreatTypeTrojan
	case "payload", "payload_delivery":
		return types.ThreatTypeMalware
	case "ransomware":
		return types.ThreatTypeRansomware
	default:
		return types.ThreatTypeMalware
	}
}
