// ABOUTME: Circuit breaker pattern for fault tolerance
// ABOUTME: Prevents cascading failures with configurable thresholds and recovery

package resilience

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Default circuit breaker configuration values.
const (
	DefaultMaxFailures      = 5
	DefaultResetTimeout     = 30 * time.Second
	DefaultHalfOpenMaxCalls = 3
)

// Circuit breaker states.
type State int

const (
	// StateClosed allows requests through normally.
	StateClosed State = iota

	// StateOpen rejects all requests immediately.
	StateOpen

	// StateHalfOpen allows limited test requests.
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// CircuitBreakerConfig configures the circuit breaker behavior.
type CircuitBreakerConfig struct {
	// MaxFailures is the threshold to open the circuit.
	// Zero uses DefaultMaxFailures.
	MaxFailures int

	// ResetTimeout is how long to wait before transitioning to half-open.
	// Zero uses DefaultResetTimeout.
	ResetTimeout time.Duration

	// HalfOpenMaxCalls is the number of test calls allowed in half-open state.
	// Zero uses DefaultHalfOpenMaxCalls.
	HalfOpenMaxCalls int

	// Name identifies this circuit breaker for logging/metrics.
	Name string
}

// Statistics holds circuit breaker metrics.
type Statistics struct {
	State               State
	TotalRequests       int64
	Successes           int64
	Failures            int64
	Rejections          int64
	ConsecutiveFailures int
	LastFailureTime     time.Time
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	mu     sync.RWMutex
	config CircuitBreakerConfig

	state               State
	consecutiveFailures int
	lastFailureTime     time.Time
	halfOpenCalls       int

	// Statistics counters.
	totalRequests atomic.Int64
	successes     atomic.Int64
	failures      atomic.Int64
	rejections    atomic.Int64
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	// Apply defaults.
	if config.MaxFailures == 0 {
		config.MaxFailures = DefaultMaxFailures
	}
	if config.ResetTimeout == 0 {
		config.ResetTimeout = DefaultResetTimeout
	}
	if config.HalfOpenMaxCalls == 0 {
		config.HalfOpenMaxCalls = DefaultHalfOpenMaxCalls
	}

	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
	}
}

// Execute runs the function through the circuit breaker.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(ctx context.Context) error) error {
	cb.totalRequests.Add(1)

	// Check if we can proceed.
	if !cb.allowRequest() {
		cb.rejections.Add(1)
		return ErrCircuitOpen
	}

	// Execute the function.
	err := fn(ctx)

	// Record result.
	cb.recordResult(err == nil)

	return err
}

// ExecuteWithFallback runs the function with a fallback if the circuit is open.
func (cb *CircuitBreaker) ExecuteWithFallback(
	ctx context.Context,
	fn func(ctx context.Context) error,
	fallback func(ctx context.Context, err error) error,
) error {
	err := cb.Execute(ctx, fn)
	if errors.Is(err, ErrCircuitOpen) {
		return fallback(ctx, err)
	}
	return err
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() State {
	cb.mu.RLock()
	state := cb.state
	lastFailure := cb.lastFailureTime
	cb.mu.RUnlock()

	// Check for automatic transition to half-open.
	if state == StateOpen && !lastFailure.IsZero() {
		if time.Since(lastFailure) >= cb.config.ResetTimeout {
			cb.mu.Lock()
			if cb.state == StateOpen {
				cb.state = StateHalfOpen
				cb.halfOpenCalls = 0
			}
			state = cb.state
			cb.mu.Unlock()
		}
	}

	return state
}

// Statistics returns current circuit breaker statistics.
func (cb *CircuitBreaker) Statistics() Statistics {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return Statistics{
		State:               cb.state,
		TotalRequests:       cb.totalRequests.Load(),
		Successes:           cb.successes.Load(),
		Failures:            cb.failures.Load(),
		Rejections:          cb.rejections.Load(),
		ConsecutiveFailures: cb.consecutiveFailures,
		LastFailureTime:     cb.lastFailureTime,
	}
}

// Reset manually resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.consecutiveFailures = 0
	cb.lastFailureTime = time.Time{}
	cb.halfOpenCalls = 0
}

// allowRequest checks if a request should be allowed.
func (cb *CircuitBreaker) allowRequest() bool {
	state := cb.State() // This handles auto-transition to half-open.

	switch state {
	case StateClosed:
		return true

	case StateOpen:
		return false

	case StateHalfOpen:
		cb.mu.Lock()
		defer cb.mu.Unlock()

		if cb.halfOpenCalls < cb.config.HalfOpenMaxCalls {
			cb.halfOpenCalls++
			return true
		}
		return false

	default:
		return false
	}
}

// recordResult records the result of an operation.
func (cb *CircuitBreaker) recordResult(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if success {
		cb.successes.Add(1)
		cb.consecutiveFailures = 0

		// In half-open, success closes the circuit.
		if cb.state == StateHalfOpen {
			cb.state = StateClosed
			cb.halfOpenCalls = 0
		}
	} else {
		cb.failures.Add(1)
		cb.consecutiveFailures++
		cb.lastFailureTime = time.Now()

		// Check if we should open the circuit.
		switch cb.state {
		case StateClosed:
			if cb.consecutiveFailures >= cb.config.MaxFailures {
				cb.state = StateOpen
			}
		case StateHalfOpen:
			// Any failure in half-open reopens the circuit.
			cb.state = StateOpen
			cb.halfOpenCalls = 0
		}
	}
}
