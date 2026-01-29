// ABOUTME: Tests for ClamAV signature database parser
// ABOUTME: Validates CVD header parsing and hash signature extraction

package feeds

import (
	"context"
	"testing"
	"time"
)

func TestClamAVFeed_Name(t *testing.T) {
	feed := NewClamAVFeed()
	if feed.Name() != "clamav" {
		t.Errorf("Name() = %q, want %q", feed.Name(), "clamav")
	}
}

func TestClamAVFeed_SetMirrors(t *testing.T) {
	feed := NewClamAVFeed()
	mirrors := []string{"https://custom.mirror.com"}
	feed.SetMirrors(mirrors)

	if len(feed.mirrors) != 1 || feed.mirrors[0] != mirrors[0] {
		t.Errorf("SetMirrors() did not set mirrors correctly")
	}
}

func TestClamAVFeed_SetDatabases(t *testing.T) {
	feed := NewClamAVFeed()
	databases := []string{"main.cvd"}
	feed.SetDatabases(databases)

	if len(feed.databases) != 1 || feed.databases[0] != databases[0] {
		t.Errorf("SetDatabases() did not set databases correctly")
	}
}

func TestParseCVDHeader_Valid(t *testing.T) {
	// Sample CVD header.
	headerData := make([]byte, 512)
	copy(headerData, []byte("ClamAV-VDB:07 Nov 2023:100:1000000:63:abcdef1234567890:signature:builder:1699372800"))

	header, err := parseCVDHeader(headerData)
	if err != nil {
		t.Fatalf("parseCVDHeader() error = %v", err)
	}

	if header.Name != "ClamAV-VDB" {
		t.Errorf("Name = %q, want %q", header.Name, "ClamAV-VDB")
	}

	if header.Version != 100 {
		t.Errorf("Version = %d, want 100", header.Version)
	}

	if header.Signatures != 1000000 {
		t.Errorf("Signatures = %d, want 1000000", header.Signatures)
	}
}

func TestParseCVDHeader_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "wrong magic",
			data: []byte("NotClamAV:data:100:1000:63:md5:sig"),
		},
		{
			name: "too few fields",
			data: []byte("ClamAV-VDB:data"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headerData := make([]byte, 512)
			copy(headerData, tt.data)

			_, err := parseCVDHeader(headerData)
			if err == nil {
				t.Error("parseCVDHeader() expected error")
			}
		})
	}
}

func TestParseHDB(t *testing.T) {
	content := []byte(`# MD5 hash signatures
44d88612fea8a8f36de82e1278abb02f:68:EICAR.Test.File
e3b0c44298fc1c149afbf4c8996fb924:0:Empty.File
invalid:0:Invalid
`)

	sigs := parseHDB(content, "test", time.Now().UTC())
	if len(sigs) != 2 {
		t.Errorf("parseHDB() got %d signatures, want 2", len(sigs))
	}

	if sigs[0].MD5 != "44d88612fea8a8f36de82e1278abb02f" {
		t.Errorf("First MD5 = %q, want EICAR MD5", sigs[0].MD5)
	}

	if sigs[0].DetectionName != "ClamAV.EICAR.Test.File" {
		t.Errorf("DetectionName = %q, want %q", sigs[0].DetectionName, "ClamAV.EICAR.Test.File")
	}
}

func TestParseHSB_SHA256(t *testing.T) {
	content := []byte(`# SHA256 hash signatures
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:EICAR.Test.File
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:0:Empty.File
`)

	sigs := parseHSB(content, "test", time.Now().UTC())
	if len(sigs) != 2 {
		t.Errorf("parseHSB() got %d signatures, want 2", len(sigs))
	}

	if sigs[0].SHA256 != "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" {
		t.Errorf("First SHA256 = %q, want EICAR SHA256", sigs[0].SHA256)
	}
}

func TestParseHSB_SHA1(t *testing.T) {
	content := []byte(`# SHA1 hash signatures
3395856ce81f2b7382dee72602f798b642f14140:68:EICAR.Test.File
`)

	sigs := parseHSB(content, "test", time.Now().UTC())
	if len(sigs) != 1 {
		t.Errorf("parseHSB() got %d signatures, want 1", len(sigs))
	}

	if sigs[0].SHA1 != "3395856ce81f2b7382dee72602f798b642f14140" {
		t.Errorf("SHA1 = %q, want EICAR SHA1", sigs[0].SHA1)
	}
}

func TestParseMDB(t *testing.T) {
	content := []byte(`# PE section MD5 signatures
512:44d88612fea8a8f36de82e1278abb02f:PE.Malware
`)

	sigs := parseMDB(content, "test", time.Now().UTC())
	if len(sigs) != 1 {
		t.Errorf("parseMDB() got %d signatures, want 1", len(sigs))
	}

	if sigs[0].MD5 != "44d88612fea8a8f36de82e1278abb02f" {
		t.Errorf("MD5 = %q, want sample MD5", sigs[0].MD5)
	}
}

func TestParseMSB(t *testing.T) {
	content := []byte(`# PE section SHA256 signatures
512:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:PE.Malware
`)

	sigs := parseMSB(content, "test", time.Now().UTC())
	if len(sigs) != 1 {
		t.Errorf("parseMSB() got %d signatures, want 1", len(sigs))
	}

	if sigs[0].SHA256 != "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" {
		t.Errorf("SHA256 = %q, want sample SHA256", sigs[0].SHA256)
	}
}

func TestIsHashFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"main.hdb", true},
		{"daily.hsb", true},
		{"test.mdb", true},
		{"test.msb", true},
		{"test.ndb", false},
		{"test.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHashFile(tt.name); got != tt.want {
				t.Errorf("isHashFile(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestClamAVFeed_ParseCVD_TooSmall(t *testing.T) {
	feed := NewClamAVFeed()
	_, err := feed.ParseCVD(context.Background(), []byte("small"))
	if err == nil {
		t.Error("ParseCVD() expected error for small data")
	}
}
