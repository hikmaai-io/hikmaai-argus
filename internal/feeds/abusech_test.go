// ABOUTME: Tests for abuse.ch malware feeds (MalwareBazaar, ThreatFox)
// ABOUTME: Validates hash list parsing and CSV parsing

package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestMalwareBazaarFeed_Parse(t *testing.T) {
	t.Parallel()

	// Sample MalwareBazaar format (plain text, one hash per line)
	sampleData := `# MalwareBazaar SHA256 Hashes
# Last update: 2024-01-15
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
invalid_hash_should_be_skipped
`

	feed := NewMalwareBazaarFeed()

	ctx := context.Background()
	sigs, err := feed.ParseData(ctx, []byte(sampleData))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Should have 2 valid signatures
	if len(sigs) != 2 {
		t.Errorf("Parse() got %d signatures, want 2", len(sigs))
	}

	// Verify first signature
	if sigs[0].SHA256 != "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" {
		t.Errorf("First signature SHA256 = %q, want EICAR hash", sigs[0].SHA256)
	}

	// Check threat type
	if sigs[0].ThreatType != types.ThreatTypeMalware {
		t.Errorf("ThreatType = %v, want ThreatTypeMalware", sigs[0].ThreatType)
	}

	// Check source
	if sigs[0].Source != "malwarebazaar" {
		t.Errorf("Source = %q, want %q", sigs[0].Source, "malwarebazaar")
	}
}

func TestMalwareBazaarFeed_Download(t *testing.T) {
	t.Parallel()

	// Mock server returning sample hash list
	sampleData := `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleData))
	}))
	defer server.Close()

	feed := NewMalwareBazaarFeed()
	feed.SetURL(server.URL)

	ctx := context.Background()
	sigs, err := feed.Fetch(ctx)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if len(sigs) != 2 {
		t.Errorf("Fetch() got %d signatures, want 2", len(sigs))
	}
}

func TestMalwareBazaarFeed_Name(t *testing.T) {
	feed := NewMalwareBazaarFeed()
	if feed.Name() != "malwarebazaar" {
		t.Errorf("Name() = %q, want %q", feed.Name(), "malwarebazaar")
	}
}

func TestThreatFoxFeed_ParseCSV(t *testing.T) {
	t.Parallel()

	// Sample ThreatFox CSV format
	sampleCSV := `first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen_utc,confidence_level,reference,tags,anonymous,reporter
"2024-01-15 00:00:00",123,"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","sha256_hash","payload","emotet","win.emotet","Emotet","","100","https://example.com","emotet","0","reporter1"
"2024-01-15 00:00:00",124,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","sha256_hash","ransomware","lockbit","win.lockbit","LockBit","","100","https://example.com","ransomware","0","reporter2"
"2024-01-15 00:00:00",125,"http://malicious.example.com/payload","url","payload","generic","","Malware","","50","","","0","reporter3"
`

	feed := NewThreatFoxFeed()

	ctx := context.Background()
	sigs, err := feed.ParseData(ctx, []byte(sampleCSV))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Should have 2 valid hash signatures (URL is skipped)
	if len(sigs) != 2 {
		t.Errorf("Parse() got %d signatures, want 2", len(sigs))
	}

	// Check first signature
	if sigs[0].SHA256 != "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" {
		t.Errorf("First signature SHA256 = %q, want EICAR hash", sigs[0].SHA256)
	}

	// Check detection name includes malware name
	if sigs[0].DetectionName != "ThreatFox.Emotet" {
		t.Errorf("DetectionName = %q, want %q", sigs[0].DetectionName, "ThreatFox.Emotet")
	}

	// Check ransomware threat type is mapped correctly
	if sigs[1].ThreatType != types.ThreatTypeRansomware {
		t.Errorf("Second signature ThreatType = %v, want ThreatTypeRansomware", sigs[1].ThreatType)
	}
}

func TestThreatFoxFeed_Name(t *testing.T) {
	feed := NewThreatFoxFeed()
	if feed.Name() != "threatfox" {
		t.Errorf("Name() = %q, want %q", feed.Name(), "threatfox")
	}
}

func TestURLhausFeed_Name(t *testing.T) {
	feed := NewURLhausFeed()
	if feed.Name() != "urlhaus" {
		t.Errorf("Name() = %q, want %q", feed.Name(), "urlhaus")
	}
}

func TestDecompressIfNeeded_PlainText(t *testing.T) {
	t.Parallel()

	data := []byte("plain text data")
	result, err := decompressIfNeeded(data)
	if err != nil {
		t.Fatalf("decompressIfNeeded() error = %v", err)
	}

	if string(result) != string(data) {
		t.Errorf("decompressIfNeeded() = %q, want %q", string(result), string(data))
	}
}
