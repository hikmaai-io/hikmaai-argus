// ABOUTME: Tests for CSV feed parser (abuse.ch format)
// ABOUTME: Covers SHA256 hash extraction and signature creation

package feeds_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hikmaai-io/hikmaai-argus/internal/feeds"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestCSVFeed_Parse(t *testing.T) {
	t.Parallel()

	// Sample abuse.ch format CSV.
	csvData := `# abuse.ch Malware Bazaar SHA256 hashes
# Generated: 2024-01-01
sha256_hash
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
`

	feed := feeds.NewCSVFeed("test", feeds.CSVConfig{
		SHA256Column: 0,
		SkipHeader:   true,
		CommentChar:  '#',
	})

	ctx := context.Background()
	sigs, err := feed.Parse(ctx, strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sigs) != 3 {
		t.Errorf("len(sigs) = %d, want 3", len(sigs))
	}

	// Verify first signature.
	if len(sigs) > 0 {
		if sigs[0].SHA256 != "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" {
			t.Errorf("sigs[0].SHA256 = %v", sigs[0].SHA256)
		}
		if sigs[0].Source != "test" {
			t.Errorf("sigs[0].Source = %v, want test", sigs[0].Source)
		}
	}
}

func TestCSVFeed_ParseWithMultipleColumns(t *testing.T) {
	t.Parallel()

	// Sample CSV with multiple columns.
	csvData := `first_seen_utc,sha256_hash,md5_hash,sha1_hash,signature
2024-01-01,275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,44d88612fea8a8f36de82e1278abb02f,3395856ce81f2b7382dee72602f798b642f14140,EICAR-Test
`

	feed := feeds.NewCSVFeed("malwarebazaar", feeds.CSVConfig{
		SHA256Column:    1,
		MD5Column:       2,
		SHA1Column:      3,
		DetectionColumn: 4,
		SkipHeader:      true,
	})

	ctx := context.Background()
	sigs, err := feed.Parse(ctx, strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sigs) != 1 {
		t.Fatalf("len(sigs) = %d, want 1", len(sigs))
	}

	sig := sigs[0]
	if sig.SHA256 != "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" {
		t.Errorf("SHA256 = %v", sig.SHA256)
	}
	if sig.MD5 != "44d88612fea8a8f36de82e1278abb02f" {
		t.Errorf("MD5 = %v", sig.MD5)
	}
	if sig.SHA1 != "3395856ce81f2b7382dee72602f798b642f14140" {
		t.Errorf("SHA1 = %v", sig.SHA1)
	}
	if sig.DetectionName != "EICAR-Test" {
		t.Errorf("DetectionName = %v, want EICAR-Test", sig.DetectionName)
	}
}

func TestCSVFeed_EmptyFile(t *testing.T) {
	t.Parallel()

	feed := feeds.NewCSVFeed("test", feeds.CSVConfig{
		SHA256Column: 0,
	})

	ctx := context.Background()
	sigs, err := feed.Parse(ctx, strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sigs) != 0 {
		t.Errorf("len(sigs) = %d, want 0", len(sigs))
	}
}

func TestCSVFeed_InvalidHashes(t *testing.T) {
	t.Parallel()

	csvData := `sha256
invalid_hash
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
too_short
`

	feed := feeds.NewCSVFeed("test", feeds.CSVConfig{
		SHA256Column: 0,
		SkipHeader:   true,
	})

	ctx := context.Background()
	sigs, err := feed.Parse(ctx, strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	// Should only have 1 valid signature.
	if len(sigs) != 1 {
		t.Errorf("len(sigs) = %d, want 1 (valid hashes only)", len(sigs))
	}
}

func TestCSVFeed_Name(t *testing.T) {
	t.Parallel()

	feed := feeds.NewCSVFeed("malwarebazaar", feeds.CSVConfig{})
	if feed.Name() != "malwarebazaar" {
		t.Errorf("Name() = %v, want malwarebazaar", feed.Name())
	}
}

func TestCSVFeed_ThreatType(t *testing.T) {
	t.Parallel()

	csvData := `sha256
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
`

	feed := feeds.NewCSVFeed("test", feeds.CSVConfig{
		SHA256Column:       0,
		SkipHeader:         true,
		DefaultThreatType:  types.ThreatTypeTrojan,
		DefaultSeverity:    types.SeverityHigh,
		DefaultDescription: "Test malware",
	})

	ctx := context.Background()
	sigs, err := feed.Parse(ctx, strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sigs) != 1 {
		t.Fatalf("len(sigs) = %d, want 1", len(sigs))
	}

	if sigs[0].ThreatType != types.ThreatTypeTrojan {
		t.Errorf("ThreatType = %v, want %v", sigs[0].ThreatType, types.ThreatTypeTrojan)
	}
	if sigs[0].Severity != types.SeverityHigh {
		t.Errorf("Severity = %v, want %v", sigs[0].Severity, types.SeverityHigh)
	}
	if sigs[0].Description != "Test malware" {
		t.Errorf("Description = %v, want 'Test malware'", sigs[0].Description)
	}
}
