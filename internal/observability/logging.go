// ABOUTME: Structured logging with slog for Loki compatibility
// ABOUTME: JSON format with trace ID injection and service metadata

package observability

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// LoggingConfig holds configuration for structured logging.
type LoggingConfig struct {
	// Log level: debug, info, warn, error.
	Level string

	// Output format: json or text.
	Format string

	// Service name to include in logs.
	ServiceName string

	// Service version to include in logs.
	Version string

	// Include source location in logs.
	AddSource bool
}

// NewLogger creates a new structured logger with the given configuration.
func NewLogger(cfg LoggingConfig, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}

	level := ParseLogLevel(cfg.Level)

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "text" {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}

	// Add service attributes if provided.
	var attrs []slog.Attr
	if cfg.ServiceName != "" {
		attrs = append(attrs, slog.String("service", cfg.ServiceName))
	}
	if cfg.Version != "" {
		attrs = append(attrs, slog.String("version", cfg.Version))
	}

	if len(attrs) > 0 {
		handler = handler.WithAttrs(attrs)
	}

	return slog.New(handler)
}

// ParseLogLevel parses a log level string into a slog.Level.
func ParseLogLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// LogWithContext logs a message with trace context.
func LogWithContext(ctx context.Context, logger *slog.Logger, level slog.Level, msg string, args ...any) {
	// Extract trace ID if present.
	traceID := ExtractTraceID(ctx)
	spanID := ExtractSpanID(ctx)

	// Add trace context to args if present.
	if traceID != "" {
		args = append(args, slog.String("trace_id", traceID))
	}
	if spanID != "" {
		args = append(args, slog.String("span_id", spanID))
	}

	logger.Log(ctx, level, msg, args...)
}

// ContextLogger wraps a logger to automatically extract trace context.
type ContextLogger struct {
	logger *slog.Logger
}

// NewContextLogger creates a new context-aware logger.
func NewContextLogger(logger *slog.Logger) *ContextLogger {
	return &ContextLogger{logger: logger}
}

// Debug logs a debug message with trace context.
func (cl *ContextLogger) Debug(ctx context.Context, msg string, args ...any) {
	LogWithContext(ctx, cl.logger, slog.LevelDebug, msg, args...)
}

// Info logs an info message with trace context.
func (cl *ContextLogger) Info(ctx context.Context, msg string, args ...any) {
	LogWithContext(ctx, cl.logger, slog.LevelInfo, msg, args...)
}

// Warn logs a warning message with trace context.
func (cl *ContextLogger) Warn(ctx context.Context, msg string, args ...any) {
	LogWithContext(ctx, cl.logger, slog.LevelWarn, msg, args...)
}

// Error logs an error message with trace context.
func (cl *ContextLogger) Error(ctx context.Context, msg string, args ...any) {
	LogWithContext(ctx, cl.logger, slog.LevelError, msg, args...)
}

// With returns a new logger with the given attributes.
func (cl *ContextLogger) With(args ...any) *ContextLogger {
	return &ContextLogger{logger: cl.logger.With(args...)}
}

// Logger returns the underlying slog.Logger.
func (cl *ContextLogger) Logger() *slog.Logger {
	return cl.logger
}

// DefaultLogger creates a default logger for production use.
func DefaultLogger(serviceName, version string) *slog.Logger {
	return NewLogger(LoggingConfig{
		Level:       "info",
		Format:      "json",
		ServiceName: serviceName,
		Version:     version,
		AddSource:   false,
	}, os.Stdout)
}
