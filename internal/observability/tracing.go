// ABOUTME: OpenTelemetry tracing setup for distributed tracing
// ABOUTME: Exports traces to OTLP endpoint (Tempo compatible)

package observability

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TracingConfig holds configuration for OpenTelemetry tracing.
type TracingConfig struct {
	// Enable tracing.
	Enabled bool

	// Service name for traces.
	ServiceName string

	// Service version.
	Version string

	// OTLP endpoint (e.g., "localhost:4317" for Tempo).
	Endpoint string

	// Use insecure connection (no TLS).
	Insecure bool

	// Sampling ratio (0.0 to 1.0). 1.0 means sample all traces.
	SamplingRatio float64
}

// TracerProvider wraps the OpenTelemetry tracer provider.
type TracerProvider struct {
	provider *sdktrace.TracerProvider
	enabled  bool
}

// NewTracerProvider creates a new OpenTelemetry tracer provider.
func NewTracerProvider(ctx context.Context, cfg TracingConfig) (*TracerProvider, error) {
	if !cfg.Enabled {
		// Return a no-op provider.
		return &TracerProvider{
			provider: sdktrace.NewTracerProvider(),
			enabled:  false,
		}, nil
	}

	// Create resource with service info.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", cfg.ServiceName),
			attribute.String("service.version", cfg.Version),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Configure OTLP exporter options.
	exporterOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		exporterOpts = append(exporterOpts, otlptracegrpc.WithInsecure())
	}

	// Create OTLP exporter.
	exporter, err := otlptracegrpc.New(ctx, exporterOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Configure sampler.
	var sampler sdktrace.Sampler
	if cfg.SamplingRatio <= 0 {
		sampler = sdktrace.NeverSample()
	} else if cfg.SamplingRatio >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SamplingRatio)
	}

	// Create tracer provider.
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global tracer provider.
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &TracerProvider{
		provider: provider,
		enabled:  true,
	}, nil
}

// Tracer returns a tracer with the given name.
func (tp *TracerProvider) Tracer(name string) trace.Tracer {
	return tp.provider.Tracer(name)
}

// Shutdown shuts down the tracer provider.
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.provider == nil {
		return nil
	}
	return tp.provider.Shutdown(ctx)
}

// IsEnabled returns whether tracing is enabled.
func (tp *TracerProvider) IsEnabled() bool {
	return tp.enabled
}

// ExtractTraceID extracts the trace ID from the context.
// Returns an empty string if no trace is present.
func ExtractTraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return ""
	}
	sc := span.SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// ExtractSpanID extracts the span ID from the context.
// Returns an empty string if no span is present.
func ExtractSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return ""
	}
	sc := span.SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return sc.SpanID().String()
}

// StartSpan starts a new span with the given name.
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return otel.Tracer("hikmaai-argus").Start(ctx, name, opts...)
}
