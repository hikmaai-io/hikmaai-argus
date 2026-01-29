// ABOUTME: ClamAV signature database parser
// ABOUTME: Parses CVD files (main.cvd, daily.cvd) extracting hash signatures

package feeds

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// ClamAV database mirrors.
var ClamAVMirrors = []string{
	"https://database.clamav.net",
	"https://packages.microsoft.com/clamav",
}

// ClamAV database files.
const (
	ClamAVMainDB   = "main.cvd"
	ClamAVDailyDB  = "daily.cvd"
	ClamAVByteDB   = "bytecode.cvd"
)

// CVD header size.
const cvdHeaderSize = 512

// ClamAVFeed downloads and parses ClamAV signature databases.
type ClamAVFeed struct {
	mirrors    []string
	databases  []string
	localDir   string // If set, read CVD files from this directory instead of downloading
	downloader *Downloader
}

// NewClamAVFeed creates a new ClamAV feed parser.
func NewClamAVFeed() *ClamAVFeed {
	return &ClamAVFeed{
		mirrors:    ClamAVMirrors,
		databases:  []string{ClamAVMainDB, ClamAVDailyDB},
		downloader: NewDownloader(nil),
	}
}

// NewClamAVFeedFromLocal creates a ClamAV feed that reads from local CVD files.
// This is more efficient when CVD files are already downloaded (e.g., by clamav-db feed).
func NewClamAVFeedFromLocal(clamDBDir string) *ClamAVFeed {
	return &ClamAVFeed{
		mirrors:    ClamAVMirrors,
		databases:  []string{ClamAVMainDB, ClamAVDailyDB},
		localDir:   clamDBDir,
		downloader: NewDownloader(nil),
	}
}

// SetLocalDir sets the local directory to read CVD files from.
// If set, the feed will read from local files instead of downloading.
func (f *ClamAVFeed) SetLocalDir(dir string) {
	f.localDir = dir
}

// Name returns the name of the feed.
func (f *ClamAVFeed) Name() string {
	return "clamav"
}

// SetMirrors overrides the default mirrors.
func (f *ClamAVFeed) SetMirrors(mirrors []string) {
	f.mirrors = mirrors
}

// SetDatabases sets which databases to download.
func (f *ClamAVFeed) SetDatabases(databases []string) {
	f.databases = databases
}

// Fetch downloads and parses ClamAV databases from mirrors.
// If localDir is set, it reads from local CVD files instead of downloading.
func (f *ClamAVFeed) Fetch(ctx context.Context) ([]*types.Signature, error) {
	var allSigs []*types.Signature

	for _, db := range f.databases {
		sigs, err := f.fetchDatabase(ctx, db)
		if err != nil {
			// Log warning but continue with other databases.
			fmt.Printf("Warning: failed to fetch %s: %v\n", db, err)
			continue
		}
		allSigs = append(allSigs, sigs...)
	}

	return allSigs, nil
}

// fetchDatabase loads and parses a single ClamAV database.
// If localDir is set, reads from local file; otherwise downloads from mirrors.
func (f *ClamAVFeed) fetchDatabase(ctx context.Context, database string) ([]*types.Signature, error) {
	// Try local file first if localDir is set.
	if f.localDir != "" {
		localPath := filepath.Join(f.localDir, database)
		if data, err := os.ReadFile(localPath); err == nil {
			fmt.Printf("  Reading %s from local file: %s\n", database, localPath)
			return f.ParseCVD(ctx, data)
		}
		// Local file doesn't exist; fall through to download.
		fmt.Printf("  Local file not found, downloading %s...\n", database)
	}

	// Download from mirrors.
	var lastErr error
	for _, mirror := range f.mirrors {
		url := fmt.Sprintf("%s/%s", strings.TrimSuffix(mirror, "/"), database)

		data, err := f.downloader.Download(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}

		sigs, err := f.ParseCVD(ctx, data)
		if err != nil {
			lastErr = err
			continue
		}

		return sigs, nil
	}

	return nil, fmt.Errorf("failed to fetch %s from all mirrors: %w", database, lastErr)
}

// ParseCVD parses a ClamAV CVD file.
func (f *ClamAVFeed) ParseCVD(ctx context.Context, data []byte) ([]*types.Signature, error) {
	if len(data) < cvdHeaderSize {
		return nil, fmt.Errorf("data too small for CVD file: %d bytes", len(data))
	}

	// Parse CVD header (first 512 bytes).
	header, err := parseCVDHeader(data[:cvdHeaderSize])
	if err != nil {
		return nil, fmt.Errorf("parsing CVD header: %w", err)
	}

	// Rest is tar.gz compressed signature data.
	tarGzData := data[cvdHeaderSize:]

	// Decompress gzip.
	gzReader, err := gzip.NewReader(bytes.NewReader(tarGzData))
	if err != nil {
		return nil, fmt.Errorf("opening gzip: %w", err)
	}
	defer gzReader.Close()

	// Read tar archive.
	tarReader := tar.NewReader(gzReader)

	var allSigs []*types.Signature
	now := time.Now().UTC()

	for {
		select {
		case <-ctx.Done():
			return allSigs, ctx.Err()
		default:
		}

		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip problematic entries.
		}

		// Only parse hash signature files.
		if !isHashFile(hdr.Name) {
			continue
		}

		// Read file content.
		content, err := io.ReadAll(io.LimitReader(tarReader, 100*1024*1024)) // 100MB limit per file
		if err != nil {
			continue
		}

		// Parse signatures based on file type.
		var sigs []*types.Signature
		switch {
		case strings.HasSuffix(hdr.Name, ".hdb"):
			sigs = parseHDB(content, header.Name, now)
		case strings.HasSuffix(hdr.Name, ".hsb"):
			sigs = parseHSB(content, header.Name, now)
		case strings.HasSuffix(hdr.Name, ".mdb"):
			sigs = parseMDB(content, header.Name, now)
		case strings.HasSuffix(hdr.Name, ".msb"):
			sigs = parseMSB(content, header.Name, now)
		}

		allSigs = append(allSigs, sigs...)
	}

	return allSigs, nil
}

// CVDHeader contains parsed CVD header information.
type CVDHeader struct {
	Name         string
	BuildTime    time.Time
	Version      int
	Signatures   int
	Functionality int
	MD5          string
	DigitalSig   string
}

// parseCVDHeader parses the 512-byte CVD header.
func parseCVDHeader(data []byte) (*CVDHeader, error) {
	// CVD header format (colon-separated):
	// ClamAV-VDB:build_time:version:sigs:functionality:md5:signature:builder:time
	headerStr := string(bytes.TrimRight(data, "\x00"))
	parts := strings.Split(headerStr, ":")

	if len(parts) < 7 {
		return nil, fmt.Errorf("invalid CVD header format")
	}

	if !strings.HasPrefix(parts[0], "ClamAV-VDB") {
		return nil, fmt.Errorf("not a valid CVD file")
	}

	header := &CVDHeader{
		Name: parts[0],
	}

	// Parse version.
	if len(parts) > 2 {
		fmt.Sscanf(parts[2], "%d", &header.Version)
	}

	// Parse signature count.
	if len(parts) > 3 {
		fmt.Sscanf(parts[3], "%d", &header.Signatures)
	}

	// MD5.
	if len(parts) > 5 {
		header.MD5 = parts[5]
	}

	// Digital signature.
	if len(parts) > 6 {
		header.DigitalSig = parts[6]
	}

	return header, nil
}

// isHashFile checks if the file contains hash signatures.
func isHashFile(name string) bool {
	hashExts := []string{".hdb", ".hsb", ".mdb", ".msb"}
	for _, ext := range hashExts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// parseHDB parses MD5 hash signature files.
// Format: MD5:FileSize:MalwareName
func parseHDB(content []byte, source string, now time.Time) []*types.Signature {
	var sigs []*types.Signature

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}

		md5Hash := strings.ToLower(parts[0])
		if !isValidMD5(md5Hash) {
			continue
		}

		detectionName := parts[2]

		sig := &types.Signature{
			MD5:           md5Hash,
			DetectionName: "ClamAV." + detectionName,
			ThreatType:    types.ThreatTypeMalware,
			Severity:      types.SeverityHigh,
			Source:        source,
			FirstSeen:     now,
			Description:   "ClamAV detection",
		}

		sigs = append(sigs, sig)
	}

	return sigs
}

// parseHSB parses SHA1/SHA256 hash signature files.
// Format: Hash:FileSize:MalwareName
func parseHSB(content []byte, source string, now time.Time) []*types.Signature {
	var sigs []*types.Signature

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}

		hashValue := strings.ToLower(parts[0])
		detectionName := parts[2]

		sig := &types.Signature{
			DetectionName: "ClamAV." + detectionName,
			ThreatType:    types.ThreatTypeMalware,
			Severity:      types.SeverityHigh,
			Source:        source,
			FirstSeen:     now,
			Description:   "ClamAV detection",
		}

		// Determine hash type by length.
		switch len(hashValue) {
		case 64:
			if isValidSHA256(hashValue) {
				sig.SHA256 = hashValue
				sigs = append(sigs, sig)
			}
		case 40:
			if isValidSHA1(hashValue) {
				sig.SHA1 = hashValue
				sigs = append(sigs, sig)
			}
		}
	}

	return sigs
}

// parseMDB parses PE section MD5 hash files.
// Format: PESectionSize:MD5:MalwareName
func parseMDB(content []byte, source string, now time.Time) []*types.Signature {
	var sigs []*types.Signature

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}

		md5Hash := strings.ToLower(parts[1])
		if !isValidMD5(md5Hash) {
			continue
		}

		detectionName := parts[2]

		sig := &types.Signature{
			MD5:           md5Hash,
			DetectionName: "ClamAV." + detectionName,
			ThreatType:    types.ThreatTypeMalware,
			Severity:      types.SeverityHigh,
			Source:        source,
			FirstSeen:     now,
			Description:   "ClamAV PE section detection",
		}

		sigs = append(sigs, sig)
	}

	return sigs
}

// parseMSB parses PE section SHA1/SHA256 hash files.
// Format: PESectionSize:Hash:MalwareName
func parseMSB(content []byte, source string, now time.Time) []*types.Signature {
	var sigs []*types.Signature

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}

		hashValue := strings.ToLower(parts[1])
		detectionName := parts[2]

		sig := &types.Signature{
			DetectionName: "ClamAV." + detectionName,
			ThreatType:    types.ThreatTypeMalware,
			Severity:      types.SeverityHigh,
			Source:        source,
			FirstSeen:     now,
			Description:   "ClamAV PE section detection",
		}

		// Determine hash type by length.
		switch len(hashValue) {
		case 64:
			if isValidSHA256(hashValue) {
				sig.SHA256 = hashValue
				sigs = append(sigs, sig)
			}
		case 40:
			if isValidSHA1(hashValue) {
				sig.SHA1 = hashValue
				sigs = append(sigs, sig)
			}
		}
	}

	return sigs
}

// Unused but reserved for potential future signature verification.
var _ = binary.BigEndian
