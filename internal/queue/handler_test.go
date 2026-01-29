// ABOUTME: Tests for NATS message handler
// ABOUTME: Covers request/reply scan messages and error handling

package queue_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hikmaai-io/hikma-av/internal/engine"
	"github.com/hikmaai-io/hikma-av/internal/feeds"
	"github.com/hikmaai-io/hikma-av/internal/queue"
)

func TestScanRequest_JSON(t *testing.T) {
	t.Parallel()

	req := queue.ScanRequest{
		Hash:      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		RequestID: "test-123",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var decoded queue.ScanRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded.Hash != req.Hash {
		t.Errorf("Hash = %v, want %v", decoded.Hash, req.Hash)
	}
	if decoded.RequestID != req.RequestID {
		t.Errorf("RequestID = %v, want %v", decoded.RequestID, req.RequestID)
	}
}

func TestScanResponse_JSON(t *testing.T) {
	t.Parallel()

	resp := queue.ScanResponse{
		RequestID: "test-123",
		Hash:      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		HashType:  "sha256",
		Status:    "malware",
		Detection: "EICAR-Test-File",
		Threat:    "testfile",
		Severity:  "low",
		Source:    "eicar",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var decoded queue.ScanResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}

	if decoded.Status != resp.Status {
		t.Errorf("Status = %v, want %v", decoded.Status, resp.Status)
	}
	if decoded.Detection != resp.Detection {
		t.Errorf("Detection = %v, want %v", decoded.Detection, resp.Detection)
	}
}

func TestHandler_ProcessRequest(t *testing.T) {
	t.Parallel()

	// Create engine with EICAR signatures.
	eng := newTestEngine(t)
	ctx := context.Background()

	eicarSigs := feeds.EICARSignatures()
	if err := eng.BatchAddSignatures(ctx, eicarSigs); err != nil {
		t.Fatalf("BatchAddSignatures() error: %v", err)
	}

	handler := queue.NewHandler(eng)

	// Test malware detection.
	req := queue.ScanRequest{
		Hash:      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		RequestID: "test-malware",
	}

	resp := handler.ProcessRequest(ctx, req)

	if resp.Status != "malware" {
		t.Errorf("Status = %v, want malware", resp.Status)
	}
	if resp.Detection != "EICAR-Test-File" {
		t.Errorf("Detection = %v, want EICAR-Test-File", resp.Detection)
	}
	if resp.RequestID != req.RequestID {
		t.Errorf("RequestID = %v, want %v", resp.RequestID, req.RequestID)
	}

	// Test clean hash.
	req = queue.ScanRequest{
		Hash:      "0000000000000000000000000000000000000000000000000000000000000000",
		RequestID: "test-clean",
	}

	resp = handler.ProcessRequest(ctx, req)

	if resp.Status != "unknown" {
		t.Errorf("Clean Status = %v, want unknown", resp.Status)
	}
}

func TestHandler_ProcessRequest_InvalidHash(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	handler := queue.NewHandler(eng)
	ctx := context.Background()

	req := queue.ScanRequest{
		Hash:      "invalid-hash",
		RequestID: "test-invalid",
	}

	resp := handler.ProcessRequest(ctx, req)

	if resp.Status != "error" {
		t.Errorf("Status = %v, want error", resp.Status)
	}
	if resp.Error == "" {
		t.Error("Error should not be empty for invalid hash")
	}
}

func TestHandler_ProcessBatch(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ctx := context.Background()

	eicarSigs := feeds.EICARSignatures()
	if err := eng.BatchAddSignatures(ctx, eicarSigs); err != nil {
		t.Fatalf("BatchAddSignatures() error: %v", err)
	}

	handler := queue.NewHandler(eng)

	reqs := []queue.ScanRequest{
		{Hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", RequestID: "1"},
		{Hash: "0000000000000000000000000000000000000000000000000000000000000000", RequestID: "2"},
		{Hash: "invalid", RequestID: "3"},
	}

	responses := handler.ProcessBatch(ctx, reqs)

	if len(responses) != 3 {
		t.Fatalf("len(responses) = %d, want 3", len(responses))
	}

	// Check malware detection.
	if responses[0].Status != "malware" {
		t.Errorf("responses[0].Status = %v, want malware", responses[0].Status)
	}

	// Check clean.
	if responses[1].Status != "unknown" {
		t.Errorf("responses[1].Status = %v, want unknown", responses[1].Status)
	}

	// Check error.
	if responses[2].Status != "error" {
		t.Errorf("responses[2].Status = %v, want error", responses[2].Status)
	}
}

func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()

	eng, err := engine.NewEngine(engine.EngineConfig{
		StoreConfig: engine.StoreConfig{
			InMemory: true,
		},
		BloomConfig: engine.BloomConfig{
			ExpectedItems:     1000,
			FalsePositiveRate: 0.01,
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	t.Cleanup(func() {
		eng.Close()
	})

	return eng
}
