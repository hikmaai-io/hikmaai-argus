// ABOUTME: Tests for EICAR test signature loader
// ABOUTME: Verifies EICAR signature generation and hash validation

package feeds_test

import (
	"testing"

	"github.com/hikmaai-io/hikmaai-argus/internal/feeds"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// Known EICAR hashes.
const (
	eicarSHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	eicarSHA1   = "3395856ce81f2b7382dee72602f798b642f14140"
	eicarMD5    = "44d88612fea8a8f36de82e1278abb02f"
)

func TestEICAR_Signatures(t *testing.T) {
	t.Parallel()

	sigs := feeds.EICARSignatures()

	if len(sigs) == 0 {
		t.Fatal("EICARSignatures() returned empty slice")
	}

	// Find the standard EICAR signature.
	var found bool
	for _, sig := range sigs {
		if sig.SHA256 == eicarSHA256 {
			found = true

			if sig.SHA1 != eicarSHA1 {
				t.Errorf("SHA1 = %v, want %v", sig.SHA1, eicarSHA1)
			}
			if sig.MD5 != eicarMD5 {
				t.Errorf("MD5 = %v, want %v", sig.MD5, eicarMD5)
			}
			if sig.DetectionName != "EICAR-Test-File" {
				t.Errorf("DetectionName = %v, want EICAR-Test-File", sig.DetectionName)
			}
			if sig.ThreatType != types.ThreatTypeTestFile {
				t.Errorf("ThreatType = %v, want %v", sig.ThreatType, types.ThreatTypeTestFile)
			}
			if sig.Source != "eicar" {
				t.Errorf("Source = %v, want eicar", sig.Source)
			}
			break
		}
	}

	if !found {
		t.Error("Standard EICAR signature not found")
	}
}

func TestEICAR_TestString(t *testing.T) {
	t.Parallel()

	testStr := feeds.EICARTestString()

	// EICAR test string should be 68 characters.
	if len(testStr) != 68 {
		t.Errorf("EICAR test string length = %d, want 68", len(testStr))
	}

	// Should start with X5O!P%@AP.
	expectedPrefix := "X5O!P%@AP"
	if len(testStr) < len(expectedPrefix) || testStr[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("EICAR test string should start with %q", expectedPrefix)
	}

	// Should end with EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*.
	expectedSuffix := "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	if len(testStr) < len(expectedSuffix) || testStr[len(testStr)-len(expectedSuffix):] != expectedSuffix {
		t.Errorf("EICAR test string should end with %q", expectedSuffix)
	}
}

func TestEICAR_ComputeHashes(t *testing.T) {
	t.Parallel()

	testStr := feeds.EICARTestString()
	sha256, sha1, md5 := feeds.ComputeHashes([]byte(testStr))

	if sha256 != eicarSHA256 {
		t.Errorf("SHA256 = %v, want %v", sha256, eicarSHA256)
	}
	if sha1 != eicarSHA1 {
		t.Errorf("SHA1 = %v, want %v", sha1, eicarSHA1)
	}
	if md5 != eicarMD5 {
		t.Errorf("MD5 = %v, want %v", md5, eicarMD5)
	}
}
