// ABOUTME: Signature type representing malware detection signatures
// ABOUTME: Contains hash values, threat information, and metadata from feeds

package types

import (
	"fmt"
	"time"
)

// ThreatType represents the category of malware threat.
type ThreatType int

const (
	// ThreatTypeUnknown represents an unknown threat type.
	ThreatTypeUnknown ThreatType = iota
	// ThreatTypeTrojan represents trojan malware.
	ThreatTypeTrojan
	// ThreatTypeVirus represents a virus.
	ThreatTypeVirus
	// ThreatTypeWorm represents a worm.
	ThreatTypeWorm
	// ThreatTypeRansomware represents ransomware.
	ThreatTypeRansomware
	// ThreatTypeAdware represents adware.
	ThreatTypeAdware
	// ThreatTypeSpyware represents spyware.
	ThreatTypeSpyware
	// ThreatTypePUP represents a potentially unwanted program.
	ThreatTypePUP
	// ThreatTypeTestFile represents a test file (e.g., EICAR).
	ThreatTypeTestFile
)

// String returns the string representation of the threat type.
func (tt ThreatType) String() string {
	switch tt {
	case ThreatTypeTrojan:
		return "trojan"
	case ThreatTypeVirus:
		return "virus"
	case ThreatTypeWorm:
		return "worm"
	case ThreatTypeRansomware:
		return "ransomware"
	case ThreatTypeAdware:
		return "adware"
	case ThreatTypeSpyware:
		return "spyware"
	case ThreatTypePUP:
		return "pup"
	case ThreatTypeTestFile:
		return "testfile"
	default:
		return "unknown"
	}
}

// Severity represents the severity level of a threat.
type Severity int

const (
	// SeverityUnknown represents an unknown severity.
	SeverityUnknown Severity = iota
	// SeverityLow represents a low severity threat.
	SeverityLow
	// SeverityMedium represents a medium severity threat.
	SeverityMedium
	// SeverityHigh represents a high severity threat.
	SeverityHigh
	// SeverityCritical represents a critical severity threat.
	SeverityCritical
)

// String returns the string representation of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Signature represents a malware signature with associated metadata.
type Signature struct {
	// Primary hash (always SHA256).
	SHA256 string `json:"sha256"`

	// Optional alternative hashes for lookup.
	SHA1 string `json:"sha1,omitempty"`
	MD5  string `json:"md5,omitempty"`

	// Detection information.
	DetectionName string     `json:"detection_name"`
	ThreatType    ThreatType `json:"threat_type"`
	Severity      Severity   `json:"severity"`

	// Metadata.
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen,omitempty"`

	// Optional extended information.
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// NewSignature creates a new Signature with the required fields.
func NewSignature(sha256, detectionName, source string) (*Signature, error) {
	if sha256 == "" {
		return nil, fmt.Errorf("sha256 is required")
	}
	if detectionName == "" {
		return nil, fmt.Errorf("detection_name is required")
	}

	return &Signature{
		SHA256:        sha256,
		DetectionName: detectionName,
		Source:        source,
		FirstSeen:     time.Now().UTC(),
	}, nil
}

// WithSHA1 sets the SHA1 hash and returns the signature for chaining.
func (s *Signature) WithSHA1(sha1 string) *Signature {
	s.SHA1 = sha1
	return s
}

// WithMD5 sets the MD5 hash and returns the signature for chaining.
func (s *Signature) WithMD5(md5 string) *Signature {
	s.MD5 = md5
	return s
}

// WithThreatType sets the threat type and returns the signature for chaining.
func (s *Signature) WithThreatType(tt ThreatType) *Signature {
	s.ThreatType = tt
	return s
}

// WithSeverity sets the severity and returns the signature for chaining.
func (s *Signature) WithSeverity(sev Severity) *Signature {
	s.Severity = sev
	return s
}

// WithDescription sets the description and returns the signature for chaining.
func (s *Signature) WithDescription(desc string) *Signature {
	s.Description = desc
	return s
}

// GetHashes returns all available hashes for this signature.
func (s *Signature) GetHashes() []Hash {
	hashes := make([]Hash, 0, 3)

	if s.SHA256 != "" {
		hashes = append(hashes, Hash{Type: HashTypeSHA256, Value: s.SHA256})
	}
	if s.SHA1 != "" {
		hashes = append(hashes, Hash{Type: HashTypeSHA1, Value: s.SHA1})
	}
	if s.MD5 != "" {
		hashes = append(hashes, Hash{Type: HashTypeMD5, Value: s.MD5})
	}

	return hashes
}
