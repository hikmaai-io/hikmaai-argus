// ABOUTME: Tests for request correlation ID system
// ABOUTME: Validates ID generation, context propagation, and HTTP extraction

package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewCorrelationID(t *testing.T) {
	t.Parallel()

	id1 := NewCorrelationID()
	id2 := NewCorrelationID()

	if id1 == "" {
		t.Error("NewCorrelationID() should not return empty string")
	}
	if id1 == id2 {
		t.Error("NewCorrelationID() should generate unique IDs")
	}
}

func TestCorrelationID_WithContext(t *testing.T) {
	t.Parallel()

	id := NewCorrelationID()
	ctx := WithCorrelationID(context.Background(), id)

	got := FromContext(ctx)
	if got != id {
		t.Errorf("FromContext() = %q, want %q", got, id)
	}
}

func TestCorrelationID_FromContext_Empty(t *testing.T) {
	t.Parallel()

	got := FromContext(context.Background())
	if got != "" {
		t.Errorf("FromContext() with no ID = %q, want empty", got)
	}
}

func TestExtractOrGenerate_WithHeader(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(CorrelationIDHeader, "test-correlation-id")

	id := ExtractOrGenerate(req)

	if id != "test-correlation-id" {
		t.Errorf("ExtractOrGenerate() = %q, want %q", id, "test-correlation-id")
	}
}

func TestExtractOrGenerate_WithoutHeader(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	id := ExtractOrGenerate(req)

	if id == "" {
		t.Error("ExtractOrGenerate() should generate ID when header missing")
	}
}

func TestCorrelationMiddleware(t *testing.T) {
	t.Parallel()

	var capturedID CorrelationID
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	wrapped := CorrelationMiddleware(handler)

	t.Run("injects_correlation_id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		if capturedID == "" {
			t.Error("Middleware should inject correlation ID into context")
		}
	})

	t.Run("preserves_existing_id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(CorrelationIDHeader, "existing-id")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		if capturedID != "existing-id" {
			t.Errorf("Middleware should preserve existing ID, got %q", capturedID)
		}
	})

	t.Run("sets_response_header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(CorrelationIDHeader, "response-test-id")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		respHeader := rec.Header().Get(CorrelationIDHeader)
		if respHeader != "response-test-id" {
			t.Errorf("Response header = %q, want %q", respHeader, "response-test-id")
		}
	})
}

func TestCorrelationID_String(t *testing.T) {
	t.Parallel()

	id := CorrelationID("test-id")
	if id.String() != "test-id" {
		t.Errorf("String() = %q, want %q", id.String(), "test-id")
	}
}
