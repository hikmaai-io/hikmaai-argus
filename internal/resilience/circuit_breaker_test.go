// ABOUTME: Tests for circuit breaker pattern implementation
// ABOUTME: Validates state transitions, failure counting, and half-open recovery

package resilience

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreaker_NewCircuitBreaker(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{})

	if cb == nil {
		t.Fatal("NewCircuitBreaker() returned nil")
	}

	if cb.State() != StateClosed {
		t.Errorf("Initial state = %v, want %v", cb.State(), StateClosed)
	}
}

func TestCircuitBreaker_Execute_Success(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{})
	ctx := context.Background()

	executed := false
	err := cb.Execute(ctx, func(ctx context.Context) error {
		executed = true
		return nil
	})

	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}
	if !executed {
		t.Error("Function was not executed")
	}
}

func TestCircuitBreaker_Execute_Failure(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{})
	ctx := context.Background()

	expectedErr := errors.New("test error")
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return expectedErr
	})

	if !errors.Is(err, expectedErr) {
		t.Errorf("Execute() error = %v, want %v", err, expectedErr)
	}
}

func TestCircuitBreaker_OpensAfterMaxFailures(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  3,
		ResetTimeout: 1 * time.Second,
	})
	ctx := context.Background()

	// Trigger max failures.
	for i := 0; i < 3; i++ {
		_ = cb.Execute(ctx, func(ctx context.Context) error {
			return errors.New("failure")
		})
	}

	if cb.State() != StateOpen {
		t.Errorf("State = %v, want %v after max failures", cb.State(), StateOpen)
	}
}

func TestCircuitBreaker_RejectsWhenOpen(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  1,
		ResetTimeout: 1 * time.Hour, // Long timeout.
	})
	ctx := context.Background()

	// Trigger failure to open.
	_ = cb.Execute(ctx, func(ctx context.Context) error {
		return errors.New("failure")
	})

	// Next call should be rejected.
	executed := false
	err := cb.Execute(ctx, func(ctx context.Context) error {
		executed = true
		return nil
	})

	if executed {
		t.Error("Function should not be executed when circuit is open")
	}
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("Execute() error = %v, want %v", err, ErrCircuitOpen)
	}
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  1,
		ResetTimeout: 50 * time.Millisecond,
	})
	ctx := context.Background()

	// Trigger failure to open.
	_ = cb.Execute(ctx, func(ctx context.Context) error {
		return errors.New("failure")
	})

	if cb.State() != StateOpen {
		t.Fatalf("State = %v, want %v", cb.State(), StateOpen)
	}

	// Wait for reset timeout.
	time.Sleep(100 * time.Millisecond)

	// State should transition to half-open on next call.
	if cb.State() != StateHalfOpen {
		t.Errorf("State = %v, want %v after timeout", cb.State(), StateHalfOpen)
	}
}

func TestCircuitBreaker_HalfOpenToClosedOnSuccess(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:      1,
		ResetTimeout:     50 * time.Millisecond,
		HalfOpenMaxCalls: 1,
	})
	ctx := context.Background()

	// Open the circuit.
	_ = cb.Execute(ctx, func(ctx context.Context) error {
		return errors.New("failure")
	})

	// Wait for half-open.
	time.Sleep(100 * time.Millisecond)

	// Successful call should close the circuit.
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return nil
	})

	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}
	if cb.State() != StateClosed {
		t.Errorf("State = %v, want %v after success in half-open", cb.State(), StateClosed)
	}
}

func TestCircuitBreaker_HalfOpenToOpenOnFailure(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:      1,
		ResetTimeout:     50 * time.Millisecond,
		HalfOpenMaxCalls: 1,
	})
	ctx := context.Background()

	// Open the circuit.
	_ = cb.Execute(ctx, func(ctx context.Context) error {
		return errors.New("failure")
	})

	// Wait for half-open.
	time.Sleep(100 * time.Millisecond)

	// Failure should re-open the circuit.
	_ = cb.Execute(ctx, func(ctx context.Context) error {
		return errors.New("another failure")
	})

	if cb.State() != StateOpen {
		t.Errorf("State = %v, want %v after failure in half-open", cb.State(), StateOpen)
	}
}

func TestCircuitBreaker_ExecuteWithFallback(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures: 1,
	})
	ctx := context.Background()

	// Open the circuit.
	_ = cb.Execute(ctx, func(ctx context.Context) error {
		return errors.New("failure")
	})

	// Execute with fallback.
	fallbackExecuted := false
	err := cb.ExecuteWithFallback(ctx,
		func(ctx context.Context) error {
			return errors.New("should not run")
		},
		func(ctx context.Context, err error) error {
			fallbackExecuted = true
			return nil
		},
	)

	if err != nil {
		t.Errorf("ExecuteWithFallback() error = %v", err)
	}
	if !fallbackExecuted {
		t.Error("Fallback was not executed")
	}
}

func TestCircuitBreaker_Statistics(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures: 10,
	})
	ctx := context.Background()

	// Execute some successes and failures.
	for i := 0; i < 5; i++ {
		_ = cb.Execute(ctx, func(ctx context.Context) error {
			return nil
		})
	}
	for i := 0; i < 3; i++ {
		_ = cb.Execute(ctx, func(ctx context.Context) error {
			return errors.New("failure")
		})
	}

	stats := cb.Statistics()

	if stats.TotalRequests != 8 {
		t.Errorf("TotalRequests = %d, want 8", stats.TotalRequests)
	}
	if stats.Successes != 5 {
		t.Errorf("Successes = %d, want 5", stats.Successes)
	}
	if stats.Failures != 3 {
		t.Errorf("Failures = %d, want 3", stats.Failures)
	}
	if stats.ConsecutiveFailures != 3 {
		t.Errorf("ConsecutiveFailures = %d, want 3", stats.ConsecutiveFailures)
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures: 1,
	})
	ctx := context.Background()

	// Open the circuit.
	_ = cb.Execute(ctx, func(ctx context.Context) error {
		return errors.New("failure")
	})

	if cb.State() != StateOpen {
		t.Fatalf("State = %v, want %v", cb.State(), StateOpen)
	}

	// Reset.
	cb.Reset()

	if cb.State() != StateClosed {
		t.Errorf("State = %v, want %v after reset", cb.State(), StateClosed)
	}

	stats := cb.Statistics()
	if stats.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0 after reset", stats.ConsecutiveFailures)
	}
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  100,
		ResetTimeout: 1 * time.Hour,
	})
	ctx := context.Background()

	var executed atomic.Int32

	// Run concurrent requests.
	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			_ = cb.Execute(ctx, func(ctx context.Context) error {
				executed.Add(1)
				return nil
			})
		}()
	}

	// Wait a bit.
	time.Sleep(100 * time.Millisecond)
	close(done)

	if executed.Load() != 100 {
		t.Errorf("Executed = %d, want 100", executed.Load())
	}
}

func TestCircuitBreakerConfig_Defaults(t *testing.T) {
	t.Parallel()

	cb := NewCircuitBreaker(CircuitBreakerConfig{})

	// Should have sensible defaults.
	if cb.config.MaxFailures == 0 {
		t.Error("MaxFailures should have default value")
	}
	if cb.config.ResetTimeout == 0 {
		t.Error("ResetTimeout should have default value")
	}
	if cb.config.HalfOpenMaxCalls == 0 {
		t.Error("HalfOpenMaxCalls should have default value")
	}
}
