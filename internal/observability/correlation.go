// ABOUTME: Request correlation ID system for distributed tracing
// ABOUTME: Generates, propagates, and extracts correlation IDs across requests

package observability

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// CorrelationIDHeader is the HTTP header name for correlation IDs.
const CorrelationIDHeader = "X-Correlation-ID"

// correlationIDKey is the context key for storing correlation IDs.
type correlationIDKey struct{}

// CorrelationID represents a unique identifier for tracing requests.
type CorrelationID string

// String returns the string representation of the correlation ID.
func (c CorrelationID) String() string {
	return string(c)
}

// NewCorrelationID generates a new unique correlation ID.
func NewCorrelationID() CorrelationID {
	return CorrelationID(uuid.New().String())
}

// WithCorrelationID returns a new context with the correlation ID attached.
func WithCorrelationID(ctx context.Context, id CorrelationID) context.Context {
	return context.WithValue(ctx, correlationIDKey{}, id)
}

// FromContext extracts the correlation ID from the context.
// Returns empty string if no correlation ID is present.
func FromContext(ctx context.Context) CorrelationID {
	id, ok := ctx.Value(correlationIDKey{}).(CorrelationID)
	if !ok {
		return ""
	}
	return id
}

// ExtractOrGenerate extracts a correlation ID from the request header,
// or generates a new one if not present.
func ExtractOrGenerate(r *http.Request) CorrelationID {
	if id := r.Header.Get(CorrelationIDHeader); id != "" {
		return CorrelationID(id)
	}
	return NewCorrelationID()
}

// CorrelationMiddleware wraps an HTTP handler to inject correlation IDs.
// It extracts the correlation ID from the X-Correlation-ID header if present,
// or generates a new one. The ID is added to the request context and
// included in the response header.
func CorrelationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := ExtractOrGenerate(r)
		ctx := WithCorrelationID(r.Context(), id)

		// Set response header.
		w.Header().Set(CorrelationIDHeader, string(id))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
