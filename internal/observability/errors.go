// ABOUTME: Structured error context for enhanced error reporting
// ABOUTME: Provides error codes, categories, stack traces, and slog integration

package observability

import (
	"fmt"
	"log/slog"
	"runtime"
	"strings"
)

// Error category constants.
const (
	CategoryTransient = "transient"  // Retryable errors (network, timeout).
	CategoryPermanent = "permanent"  // Non-retryable errors (invalid input).
	CategoryUserError = "user_error" // Errors caused by user input.
)

// ErrorContext provides structured context for errors.
type ErrorContext struct {
	// Code is a unique error identifier (e.g., "SCAN_TIMEOUT").
	Code string `json:"code"`

	// Category classifies the error type (transient, permanent, user_error).
	Category string `json:"category"`

	// Operation is the operation that failed (e.g., "clamav_scan").
	Operation string `json:"operation"`

	// StackTrace contains the call stack if captured.
	StackTrace string `json:"stack_trace,omitempty"`

	// Details contains additional error context.
	Details any `json:"details,omitempty"`

	// Err is the underlying error if any.
	Err error `json:"-"`
}

// NewErrorContext creates a new error context.
func NewErrorContext(code, category, operation string) *ErrorContext {
	return &ErrorContext{
		Code:      code,
		Category:  category,
		Operation: operation,
	}
}

// WithStack captures the current call stack.
func (e *ErrorContext) WithStack() *ErrorContext {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(2, pcs[:])

	var sb strings.Builder
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		// Skip runtime frames.
		if strings.Contains(frame.Function, "runtime.") {
			if !more {
				break
			}
			continue
		}
		fmt.Fprintf(&sb, "%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}
	e.StackTrace = sb.String()
	return e
}

// WithDetails adds additional context details.
func (e *ErrorContext) WithDetails(details any) *ErrorContext {
	e.Details = details
	return e
}

// WithError attaches the underlying error.
func (e *ErrorContext) WithError(err error) *ErrorContext {
	e.Err = err
	return e
}

// IsRetryable returns true if the error is retryable.
func (e *ErrorContext) IsRetryable() bool {
	return e.Category == CategoryTransient
}

// Error implements the error interface.
func (e *ErrorContext) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %s: %v", e.Code, e.Category, e.Operation, e.Err)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Code, e.Category, e.Operation)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *ErrorContext) Unwrap() error {
	return e.Err
}

// LogValue implements slog.LogValuer for structured logging.
func (e *ErrorContext) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("code", e.Code),
		slog.String("category", e.Category),
		slog.String("operation", e.Operation),
		slog.Bool("is_retryable", e.IsRetryable()),
	}

	if e.StackTrace != "" {
		attrs = append(attrs, slog.String("stack_trace", e.StackTrace))
	}

	if e.Details != nil {
		attrs = append(attrs, slog.Any("details", e.Details))
	}

	if e.Err != nil {
		attrs = append(attrs, slog.String("error", e.Err.Error()))
	}

	return slog.GroupValue(attrs...)
}
