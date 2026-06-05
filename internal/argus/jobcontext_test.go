// ABOUTME: Tests that in-flight Argus jobs survive daemon SIGTERM so they publish completion.
// ABOUTME: Regression guard for scans orphaned by a tool-argus pod rollout mid-job.

//nolint:testpackage // tests the unexported jobContext, like worker_test.go
package argus

import (
	"context"
	"testing"
	"time"
)

// TestJobContext_SurvivesParentCancel pins the core fix: once a job is picked
// up, its processing context must NOT be cancelled when the daemon's SIGTERM
// context is cancelled. Otherwise a rollout mid-scan aborts the scanner and the
// completion is never published, leaving the AS3 worker blocked until timeout.
func TestJobContext_SurvivesParentCancel(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	jobCtx := jobContext(parent)

	cancel() // daemon receives SIGTERM

	select {
	case <-jobCtx.Done():
		t.Fatal("job context was cancelled by parent SIGTERM; in-flight scan would abort before publishing completion")
	default:
		// expected: job keeps running so it can finish and publish.
	}
	if err := jobCtx.Err(); err != nil {
		t.Fatalf("job context should have no error after parent cancel, got %v", err)
	}
}

// TestJobContext_PreservesValues ensures request-scoped values (trace, etc.)
// still flow into the decoupled job context.
func TestJobContext_PreservesValues(t *testing.T) {
	type ctxKey string
	const k ctxKey = "trace_id"
	parent := context.WithValue(context.Background(), k, "abc-123")

	jobCtx := jobContext(parent)

	if got := jobCtx.Value(k); got != "abc-123" {
		t.Fatalf("job context dropped parent value: got %v, want abc-123", got)
	}
}

// TestJobContext_StillCancellableDownstream documents that the decoupled context
// is a normal parent: callers layer their own timeout/cancel (the per-task
// timeout and the user-cancellation listener) on top of it as before.
func TestJobContext_StillCancellableDownstream(t *testing.T) {
	jobCtx := jobContext(context.Background())

	taskCtx, taskCancel := context.WithTimeout(jobCtx, 50*time.Millisecond)
	defer taskCancel()

	select {
	case <-taskCtx.Done():
		// expected once the downstream timeout fires.
	case <-time.After(time.Second):
		t.Fatal("downstream timeout context never fired")
	}
}
