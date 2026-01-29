// ABOUTME: NATS message handler for scan requests
// ABOUTME: Processes scan requests and returns results via reply

package queue

import (
	"context"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// Handler processes scan requests using the lookup engine.
type Handler struct {
	engine       *engine.Engine
	trivyScanner *trivy.Scanner
}

// NewHandler creates a new message handler.
func NewHandler(eng *engine.Engine) *Handler {
	return &Handler{
		engine: eng,
	}
}

// NewHandlerWithTrivy creates a new message handler with Trivy support.
func NewHandlerWithTrivy(eng *engine.Engine, trivyScanner *trivy.Scanner) *Handler {
	return &Handler{
		engine:       eng,
		trivyScanner: trivyScanner,
	}
}

// ProcessRequest processes a single scan request and returns the response.
func (h *Handler) ProcessRequest(ctx context.Context, req ScanRequest) ScanResponse {
	resp := ScanResponse{
		RequestID: req.RequestID,
		Hash:      req.Hash,
		ScannedAt: time.Now().UTC(),
	}

	// Parse the hash.
	hash, err := types.ParseHash(req.Hash)
	if err != nil {
		resp.Status = "error"
		resp.Error = err.Error()
		return resp
	}

	resp.HashType = hash.Type.String()

	// Perform lookup.
	result, err := h.engine.Lookup(ctx, hash)
	if err != nil {
		resp.Status = "error"
		resp.Error = err.Error()
		resp.LookupTimeMs = result.LookupTimeMs
		resp.BloomHit = result.BloomHit
		return resp
	}

	// Convert result to response.
	resp.Status = result.Status.String()
	resp.LookupTimeMs = result.LookupTimeMs
	resp.BloomHit = result.BloomHit

	if result.Signature != nil {
		resp.Detection = result.Signature.DetectionName
		resp.Threat = result.Signature.ThreatType.String()
		resp.Severity = result.Signature.Severity.String()
		resp.Source = result.Signature.Source
	}

	return resp
}

// ProcessBatch processes multiple scan requests and returns all responses.
func (h *Handler) ProcessBatch(ctx context.Context, reqs []ScanRequest) []ScanResponse {
	responses := make([]ScanResponse, 0, len(reqs))

	for _, req := range reqs {
		select {
		case <-ctx.Done():
			// Context cancelled; return partial results.
			return responses
		default:
		}

		resp := h.ProcessRequest(ctx, req)
		responses = append(responses, resp)
	}

	return responses
}

// ProcessTrivyRequest processes a dependency scan request and returns the response.
func (h *Handler) ProcessTrivyRequest(ctx context.Context, req TrivyScanRequest) TrivyScanResponse {
	resp := TrivyScanResponse{
		RequestID: req.RequestID,
		ScannedAt: time.Now().UTC(),
	}

	if h.trivyScanner == nil {
		resp.Status = "error"
		resp.Error = "trivy scanning is not enabled"
		return resp
	}

	result, err := h.trivyScanner.ScanPackages(ctx, req.Packages, req.SeverityFilter)
	if err != nil {
		resp.Status = "error"
		resp.Error = err.Error()
		return resp
	}

	resp.Status = "completed"
	resp.Summary = &result.Summary
	resp.Vulnerabilities = result.Vulnerabilities
	resp.ScanTimeMs = result.ScanTimeMs
	resp.ScannedAt = result.ScannedAt

	return resp
}

// ResultToResponse converts an engine Result to a ScanResponse.
func ResultToResponse(result types.Result, requestID string) ScanResponse {
	resp := ScanResponse{
		RequestID:    requestID,
		Hash:         result.Hash.Value,
		HashType:     result.Hash.Type.String(),
		Status:       result.Status.String(),
		LookupTimeMs: result.LookupTimeMs,
		BloomHit:     result.BloomHit,
		ScannedAt:    result.ScannedAt,
	}

	if result.Signature != nil {
		resp.Detection = result.Signature.DetectionName
		resp.Threat = result.Signature.ThreatType.String()
		resp.Severity = result.Signature.Severity.String()
		resp.Source = result.Signature.Source
	}

	if result.Error != "" {
		resp.Error = result.Error
	}

	return resp
}
