// ABOUTME: Tests for Hash type validation and parsing
// ABOUTME: Covers SHA256, SHA1, MD5 hash detection and validation

package types_test

import (
	"testing"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestHashType_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hashType types.HashType
		want     string
	}{
		{name: "SHA256", hashType: types.HashTypeSHA256, want: "sha256"},
		{name: "SHA1", hashType: types.HashTypeSHA1, want: "sha1"},
		{name: "MD5", hashType: types.HashTypeMD5, want: "md5"},
		{name: "Unknown", hashType: types.HashTypeUnknown, want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.hashType.String(); got != tt.want {
				t.Errorf("HashType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantType   types.HashType
		wantValue  string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:      "valid SHA256 lowercase",
			input:     "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
			wantType:  types.HashTypeSHA256,
			wantValue: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		},
		{
			name:      "valid SHA256 uppercase",
			input:     "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F",
			wantType:  types.HashTypeSHA256,
			wantValue: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		},
		{
			name:      "valid SHA1",
			input:     "3395856ce81f2b7382dee72602f798b642f14140",
			wantType:  types.HashTypeSHA1,
			wantValue: "3395856ce81f2b7382dee72602f798b642f14140",
		},
		{
			name:      "valid MD5",
			input:     "44d88612fea8a8f36de82e1278abb02f",
			wantType:  types.HashTypeMD5,
			wantValue: "44d88612fea8a8f36de82e1278abb02f",
		},
		{
			name:       "empty input",
			input:      "",
			wantErr:    true,
			wantErrMsg: "empty hash",
		},
		{
			name:       "invalid characters",
			input:      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0g",
			wantErr:    true,
			wantErrMsg: "invalid hex characters",
		},
		{
			name:       "invalid length",
			input:      "275a021bbfb6489e54d471899f7db9",
			wantErr:    true,
			wantErrMsg: "invalid hash length",
		},
		{
			name:      "with whitespace trimmed",
			input:     "  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  ",
			wantType:  types.HashTypeSHA256,
			wantValue: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := types.ParseHash(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseHash() expected error containing %q, got nil", tt.wantErrMsg)
					return
				}
				if tt.wantErrMsg != "" && !containsString(err.Error(), tt.wantErrMsg) {
					t.Errorf("ParseHash() error = %v, want error containing %q", err, tt.wantErrMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseHash() unexpected error: %v", err)
				return
			}

			if got.Type != tt.wantType {
				t.Errorf("ParseHash() type = %v, want %v", got.Type, tt.wantType)
			}
			if got.Value != tt.wantValue {
				t.Errorf("ParseHash() value = %v, want %v", got.Value, tt.wantValue)
			}
		})
	}
}

func TestHash_Key(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hash types.Hash
		want string
	}{
		{
			name: "SHA256 key",
			hash: types.Hash{Type: types.HashTypeSHA256, Value: "abc123"},
			want: "sha256:abc123",
		},
		{
			name: "SHA1 key",
			hash: types.Hash{Type: types.HashTypeSHA1, Value: "def456"},
			want: "sha1:def456",
		},
		{
			name: "MD5 key",
			hash: types.Hash{Type: types.HashTypeMD5, Value: "789ghi"},
			want: "md5:789ghi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.hash.Key(); got != tt.want {
				t.Errorf("Hash.Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHash_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hash types.Hash
		want bool
	}{
		{
			name: "valid SHA256",
			hash: types.Hash{Type: types.HashTypeSHA256, Value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"},
			want: true,
		},
		{
			name: "valid SHA1",
			hash: types.Hash{Type: types.HashTypeSHA1, Value: "3395856ce81f2b7382dee72602f798b642f14140"},
			want: true,
		},
		{
			name: "valid MD5",
			hash: types.Hash{Type: types.HashTypeMD5, Value: "44d88612fea8a8f36de82e1278abb02f"},
			want: true,
		},
		{
			name: "empty value",
			hash: types.Hash{Type: types.HashTypeSHA256, Value: ""},
			want: false,
		},
		{
			name: "unknown type",
			hash: types.Hash{Type: types.HashTypeUnknown, Value: "abc"},
			want: false,
		},
		{
			name: "wrong length for type",
			hash: types.Hash{Type: types.HashTypeSHA256, Value: "abc"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.hash.IsValid(); got != tt.want {
				t.Errorf("Hash.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
