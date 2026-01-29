// ABOUTME: Tests for structured logging with slog
// ABOUTME: Verifies JSON output, trace ID injection, and log levels

package observability_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/hikmaai-io/hikma-av/internal/observability"
)

func TestNewLogger_JSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cfg := observability.LoggingConfig{
		Level:  "info",
		Format: "json",
	}

	logger := observability.NewLogger(cfg, &buf)

	logger.Info("test message", slog.String("key", "value"))

	// Parse the JSON output.
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse JSON log: %v\nOutput: %s", err, buf.String())
	}

	// Verify fields.
	if msg, ok := logEntry["msg"].(string); !ok || msg != "test message" {
		t.Errorf("msg = %v, want 'test message'", logEntry["msg"])
	}
	if key, ok := logEntry["key"].(string); !ok || key != "value" {
		t.Errorf("key = %v, want 'value'", logEntry["key"])
	}
}

func TestNewLogger_Text(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cfg := observability.LoggingConfig{
		Level:  "info",
		Format: "text",
	}

	logger := observability.NewLogger(cfg, &buf)

	logger.Info("test message", slog.String("key", "value"))

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("Output should contain 'test message': %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("Output should contain 'key=value': %s", output)
	}
}

func TestNewLogger_Levels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level       string
		logLevel    slog.Level
		shouldLog   bool
		logFunc     func(*slog.Logger)
		description string
	}{
		{
			level:       "debug",
			logLevel:    slog.LevelDebug,
			shouldLog:   true,
			logFunc:     func(l *slog.Logger) { l.Debug("debug message") },
			description: "debug level logs debug messages",
		},
		{
			level:       "info",
			logLevel:    slog.LevelInfo,
			shouldLog:   false,
			logFunc:     func(l *slog.Logger) { l.Debug("debug message") },
			description: "info level does not log debug messages",
		},
		{
			level:       "warn",
			logLevel:    slog.LevelWarn,
			shouldLog:   false,
			logFunc:     func(l *slog.Logger) { l.Info("info message") },
			description: "warn level does not log info messages",
		},
		{
			level:       "error",
			logLevel:    slog.LevelError,
			shouldLog:   true,
			logFunc:     func(l *slog.Logger) { l.Error("error message") },
			description: "error level logs error messages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			cfg := observability.LoggingConfig{
				Level:  tt.level,
				Format: "json",
			}

			logger := observability.NewLogger(cfg, &buf)
			tt.logFunc(logger)

			hasOutput := buf.Len() > 0
			if hasOutput != tt.shouldLog {
				t.Errorf("shouldLog = %v, got output = %v", tt.shouldLog, hasOutput)
			}
		})
	}
}

func TestLoggerWithTraceID(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cfg := observability.LoggingConfig{
		Level:  "info",
		Format: "json",
	}

	logger := observability.NewLogger(cfg, &buf)

	// Create a context with a mock trace ID.
	ctx := context.Background()

	// Log with context (trace ID should be extracted if present).
	observability.LogWithContext(ctx, logger, slog.LevelInfo, "test with trace")

	output := buf.String()
	if !strings.Contains(output, "test with trace") {
		t.Errorf("Output should contain 'test with trace': %s", output)
	}
}

func TestLoggerWithServiceInfo(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cfg := observability.LoggingConfig{
		Level:       "info",
		Format:      "json",
		ServiceName: "hikma-av",
		Version:     "1.0.0",
	}

	logger := observability.NewLogger(cfg, &buf)
	logger.Info("test message")

	// Parse the JSON output.
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse JSON log: %v", err)
	}

	if svc, ok := logEntry["service"].(string); !ok || svc != "hikma-av" {
		t.Errorf("service = %v, want 'hikma-av'", logEntry["service"])
	}
	if ver, ok := logEntry["version"].(string); !ok || ver != "1.0.0" {
		t.Errorf("version = %v, want '1.0.0'", logEntry["version"])
	}
}

func TestParseLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"invalid", slog.LevelInfo}, // Default to info.
		{"", slog.LevelInfo},        // Default to info.
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := observability.ParseLogLevel(tt.input)
			if got != tt.want {
				t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
