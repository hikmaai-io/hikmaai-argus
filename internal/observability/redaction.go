// ABOUTME: Sensitive data redaction for secure logging
// ABOUTME: Masks passwords, tokens, API keys, and other secrets in logs

package observability

import (
	"regexp"
	"strings"
)

// RedactionPlaceholder is the replacement text for redacted values.
const RedactionPlaceholder = "[REDACTED]"

// sensitivePatterns contains regex patterns for sensitive data in strings.
// Use [^\s&]+ to match values that stop at whitespace or & (for query params).
var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd)=[^\s&]+`),
	regexp.MustCompile(`(?i)(token|auth_token|access_token)=[^\s&]+`),
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)=[^\s&]+`),
	regexp.MustCompile(`(?i)(secret|client_secret)=[^\s&]+`),
	regexp.MustCompile(`(?i)Bearer\s+[^\s]+`),
}

// sensitiveReplacements contains the replacement patterns.
var sensitiveReplacements = []string{
	"${1}=" + RedactionPlaceholder,
	"${1}=" + RedactionPlaceholder,
	"${1}=" + RedactionPlaceholder,
	"${1}=" + RedactionPlaceholder,
	"Bearer " + RedactionPlaceholder,
}

// sensitiveKeyPatterns are patterns for sensitive map keys.
var sensitiveKeyPatterns = []string{
	"password",
	"passwd",
	"pwd",
	"token",
	"secret",
	"api_key",
	"api-key",
	"apikey",
	"auth",
	"authorization",
	"credential",
	"private_key",
	"private-key",
	"privatekey",
}

// RedactSensitive replaces sensitive data in a string with [REDACTED].
func RedactSensitive(value string) string {
	result := value
	for i, pattern := range sensitivePatterns {
		result = pattern.ReplaceAllString(result, sensitiveReplacements[i])
	}
	return result
}

// RedactMap redacts sensitive values in a map recursively.
func RedactMap(m map[string]any) map[string]any {
	result := make(map[string]any, len(m))

	for k, v := range m {
		if IsSensitiveKey(k) {
			result[k] = RedactionPlaceholder
			continue
		}

		switch val := v.(type) {
		case string:
			result[k] = RedactSensitive(val)
		case map[string]any:
			result[k] = RedactMap(val)
		case []any:
			result[k] = redactSlice(val)
		default:
			result[k] = v
		}
	}

	return result
}

// redactSlice redacts sensitive values in a slice recursively.
func redactSlice(s []any) []any {
	result := make([]any, len(s))
	for i, v := range s {
		switch val := v.(type) {
		case string:
			result[i] = RedactSensitive(val)
		case map[string]any:
			result[i] = RedactMap(val)
		case []any:
			result[i] = redactSlice(val)
		default:
			result[i] = v
		}
	}
	return result
}

// IsSensitiveKey returns true if the key name suggests sensitive data.
func IsSensitiveKey(key string) bool {
	lowerKey := strings.ToLower(key)
	for _, pattern := range sensitiveKeyPatterns {
		if strings.Contains(lowerKey, pattern) {
			return true
		}
	}
	return false
}
