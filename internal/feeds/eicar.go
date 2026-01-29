// ABOUTME: EICAR test signature loader
// ABOUTME: Provides the standard EICAR test file signature for validation

package feeds

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/hikmaai-io/hikma-av/internal/types"
)

// EICAR test string (68 characters).
// This is the standard EICAR antivirus test file content.
// See: https://www.eicar.org/download-anti-malware-testfile/
const eicarTestString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

// Known EICAR hashes (pre-computed for validation).
const (
	eicarKnownSHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	eicarKnownSHA1   = "3395856ce81f2b7382dee72602f798b642f14140"
	eicarKnownMD5    = "44d88612fea8a8f36de82e1278abb02f"
)

// EICARTestString returns the standard EICAR test string.
func EICARTestString() string {
	return eicarTestString
}

// EICARSignatures returns the built-in EICAR test signatures.
func EICARSignatures() []*types.Signature {
	return []*types.Signature{
		{
			SHA256:        eicarKnownSHA256,
			SHA1:          eicarKnownSHA1,
			MD5:           eicarKnownMD5,
			DetectionName: "EICAR-Test-File",
			ThreatType:    types.ThreatTypeTestFile,
			Severity:      types.SeverityLow,
			Source:        "eicar",
			FirstSeen:     time.Date(1996, 1, 1, 0, 0, 0, 0, time.UTC),
			Description:   "EICAR Anti-Virus Test File - not a real threat",
			References:    []string{"https://www.eicar.org/download-anti-malware-testfile/"},
			Tags:          []string{"test", "eicar"},
		},
	}
}

// ComputeHashes computes SHA256, SHA1, and MD5 hashes for the given data.
func ComputeHashes(data []byte) (sha256Hex, sha1Hex, md5Hex string) {
	// SHA256
	h256 := sha256.Sum256(data)
	sha256Hex = hex.EncodeToString(h256[:])

	// SHA1
	h1 := sha1.Sum(data)
	sha1Hex = hex.EncodeToString(h1[:])

	// MD5
	hMD5 := md5.Sum(data)
	md5Hex = hex.EncodeToString(hMD5[:])

	return
}

// VerifyEICARHashes validates that our EICAR hashes are correct.
func VerifyEICARHashes() bool {
	sha256, sha1, md5 := ComputeHashes([]byte(eicarTestString))
	return sha256 == eicarKnownSHA256 &&
		sha1 == eicarKnownSHA1 &&
		md5 == eicarKnownMD5
}
