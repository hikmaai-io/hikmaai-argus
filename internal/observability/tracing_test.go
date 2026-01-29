// ABOUTME: Tests for OpenTelemetry tracing setup
// ABOUTME: Verifies tracer provider creation and span export configuration

package observability_test

import (
	"context"
	"testing"

	"github.com/hikmaai-io/hikmaai-argus/internal/observability"
)

func TestNewTracerProvider_NoOp(t *testing.T) {
	t.Parallel()

	cfg := observability.TracingConfig{
		Enabled: false,
	}

	tp, err := observability.NewTracerProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewTracerProvider() error: %v", err)
	}

	if tp == nil {
		t.Fatal("TracerProvider should not be nil even when disabled")
	}
}

func TestNewTracerProvider_WithEndpoint(t *testing.T) {
	t.Parallel()

	cfg := observability.TracingConfig{
		Enabled:     true,
		ServiceName: "hikmaai-argus-test",
		Endpoint:    "localhost:4317",
		Insecure:    true,
	}

	// This will fail to connect but should not error during creation.
	tp, err := observability.NewTracerProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewTracerProvider() error: %v", err)
	}

	if tp == nil {
		t.Fatal("TracerProvider should not be nil")
	}

	// Cleanup.
	if err := tp.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown() error: %v", err)
	}
}

func TestTracer_StartSpan(t *testing.T) {
	t.Parallel()

	cfg := observability.TracingConfig{
		Enabled:     false, // Use no-op tracer for tests.
		ServiceName: "hikmaai-argus-test",
	}

	tp, err := observability.NewTracerProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewTracerProvider() error: %v", err)
	}
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")

	if ctx == nil {
		t.Error("Context should not be nil")
	}
	if span == nil {
		t.Error("Span should not be nil")
	}

	span.End()
}

func TestExtractTraceID(t *testing.T) {
	t.Parallel()

	// Test with no trace in context.
	ctx := context.Background()
	traceID := observability.ExtractTraceID(ctx)
	if traceID != "" {
		t.Errorf("ExtractTraceID() = %v, want empty string for context without trace", traceID)
	}
}
