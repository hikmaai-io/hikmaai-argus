// ABOUTME: Tests for sensitive data redaction system
// ABOUTME: Validates pattern matching and masking for secrets, tokens, and passwords

package observability

import (
	"testing"
)

func TestRedactSensitive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "password_query_param",
			input:    "url?password=secret123",
			expected: "url?password=[REDACTED]",
		},
		{
			name:     "token_query_param",
			input:    "url?token=abc123xyz",
			expected: "url?token=[REDACTED]",
		},
		{
			name:     "api_key_query_param",
			input:    "url?api_key=sk-123456",
			expected: "url?api_key=[REDACTED]",
		},
		{
			name:     "api-key_with_dash",
			input:    "url?api-key=sk-123456",
			expected: "url?api-key=[REDACTED]",
		},
		{
			name:     "secret_query_param",
			input:    "url?secret=mysecretvalue",
			expected: "url?secret=[REDACTED]",
		},
		{
			name:     "no_sensitive_data",
			input:    "normal text without secrets",
			expected: "normal text without secrets",
		},
		{
			name:     "multiple_params",
			input:    "url?user=john&password=secret&token=abc",
			expected: "url?user=john&password=[REDACTED]&token=[REDACTED]",
		},
		{
			name:     "bearer_token",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expected: "Authorization: Bearer [REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RedactSensitive(tt.input)
			if got != tt.expected {
				t.Errorf("RedactSensitive() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRedactMap(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"username": "john",
		"password": "secret123",
		"api_key":  "sk-123456",
		"data": map[string]any{
			"token":  "abc123",
			"normal": "value",
		},
	}

	result := RedactMap(input)

	if result["username"] != "john" {
		t.Errorf("username should not be redacted, got %v", result["username"])
	}
	if result["password"] != "[REDACTED]" {
		t.Errorf("password should be redacted, got %v", result["password"])
	}
	if result["api_key"] != "[REDACTED]" {
		t.Errorf("api_key should be redacted, got %v", result["api_key"])
	}

	nested := result["data"].(map[string]any)
	if nested["token"] != "[REDACTED]" {
		t.Errorf("nested token should be redacted, got %v", nested["token"])
	}
	if nested["normal"] != "value" {
		t.Errorf("nested normal should not be redacted, got %v", nested["normal"])
	}
}

func TestSensitiveKeys(t *testing.T) {
	t.Parallel()

	sensitiveKeys := []string{
		"password",
		"token",
		"secret",
		"api_key",
		"api-key",
		"apikey",
		"auth",
		"authorization",
		"credential",
		"private_key",
	}

	for _, key := range sensitiveKeys {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			if !IsSensitiveKey(key) {
				t.Errorf("IsSensitiveKey(%q) = false, want true", key)
			}
		})
	}
}

func TestIsSensitiveKey_CaseInsensitive(t *testing.T) {
	t.Parallel()

	tests := []string{
		"PASSWORD",
		"Password",
		"API_KEY",
		"Api_Key",
		"TOKEN",
		"Token",
	}

	for _, key := range tests {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			if !IsSensitiveKey(key) {
				t.Errorf("IsSensitiveKey(%q) = false, want true", key)
			}
		})
	}
}
