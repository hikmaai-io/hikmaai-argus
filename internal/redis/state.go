// ABOUTME: Redis state manager for job status tracking using Hash data structure
// ABOUTME: Provides atomic field updates, JSON serialization, and TTL management

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// StateManagerConfig holds configuration for the state manager.
type StateManagerConfig struct {
	// KeyPrefix is prepended to job IDs to form the full key.
	// Example: "job_state:" results in keys like "prefix:job_state:job-123".
	KeyPrefix string

	// DefaultTTL is the default time-to-live for state entries.
	DefaultTTL time.Duration
}

// StateManager manages job state in Redis using Hash data structures.
type StateManager struct {
	client     *Client
	keyPrefix  string
	defaultTTL time.Duration
}

// NewStateManager creates a new state manager.
func NewStateManager(client *Client, cfg StateManagerConfig) *StateManager {
	return &StateManager{
		client:     client,
		keyPrefix:  cfg.KeyPrefix,
		defaultTTL: cfg.DefaultTTL,
	}
}

// JobKey returns the full Redis key for a job ID.
// Combines client prefix + state prefix + job ID.
func (m *StateManager) JobKey(jobID string) string {
	return m.client.PrefixedKey(m.keyPrefix + jobID)
}

// SetField sets a single field in the job state hash.
func (m *StateManager) SetField(ctx context.Context, jobID, field, value string) error {
	key := m.JobKey(jobID)
	if err := m.client.Redis().HSet(ctx, key, field, value).Err(); err != nil {
		return fmt.Errorf("setting field %s on %s: %w", field, key, err)
	}
	return nil
}

// SetFields sets multiple fields in the job state hash atomically.
func (m *StateManager) SetFields(ctx context.Context, jobID string, fields map[string]string) error {
	if len(fields) == 0 {
		return nil
	}

	key := m.JobKey(jobID)

	// Convert to []any for HSet.
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}

	if err := m.client.Redis().HSet(ctx, key, args...).Err(); err != nil {
		return fmt.Errorf("setting %d fields on %s: %w", len(fields), key, err)
	}
	return nil
}

// SetJSON sets a field with a JSON-encoded value.
func (m *StateManager) SetJSON(ctx context.Context, jobID, field string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshaling value for field %s: %w", field, err)
	}
	return m.SetField(ctx, jobID, field, string(data))
}

// GetField retrieves a single field from the job state hash.
func (m *StateManager) GetField(ctx context.Context, jobID, field string) (string, error) {
	key := m.JobKey(jobID)
	val, err := m.client.Redis().HGet(ctx, key, field).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("field %s not found on %s: %w", field, key, err)
		}
		return "", fmt.Errorf("getting field %s from %s: %w", field, key, err)
	}
	return val, nil
}

// GetJSON retrieves a field and unmarshals it from JSON.
func (m *StateManager) GetJSON(ctx context.Context, jobID, field string, dest any) error {
	val, err := m.GetField(ctx, jobID, field)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(val), dest); err != nil {
		return fmt.Errorf("unmarshaling field %s: %w", field, err)
	}
	return nil
}

// GetAllFields retrieves all fields from the job state hash.
func (m *StateManager) GetAllFields(ctx context.Context, jobID string) (map[string]string, error) {
	key := m.JobKey(jobID)
	result, err := m.client.Redis().HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("getting all fields from %s: %w", key, err)
	}
	return result, nil
}

// SetTTL sets the time-to-live for a job state entry.
func (m *StateManager) SetTTL(ctx context.Context, jobID string, ttl time.Duration) error {
	key := m.JobKey(jobID)
	if err := m.client.Redis().Expire(ctx, key, ttl).Err(); err != nil {
		return fmt.Errorf("setting TTL on %s: %w", key, err)
	}
	return nil
}

// Delete removes the entire job state entry.
func (m *StateManager) Delete(ctx context.Context, jobID string) error {
	key := m.JobKey(jobID)
	if err := m.client.Redis().Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("deleting %s: %w", key, err)
	}
	return nil
}

// InitState initializes a new job state with the given fields and default TTL.
func (m *StateManager) InitState(ctx context.Context, jobID string, fields map[string]string) error {
	if err := m.SetFields(ctx, jobID, fields); err != nil {
		return fmt.Errorf("initializing state: %w", err)
	}

	if m.defaultTTL > 0 {
		if err := m.SetTTL(ctx, jobID, m.defaultTTL); err != nil {
			return fmt.Errorf("setting default TTL: %w", err)
		}
	}

	return nil
}

// Exists checks if a job state entry exists.
func (m *StateManager) Exists(ctx context.Context, jobID string) (bool, error) {
	key := m.JobKey(jobID)
	n, err := m.client.Redis().Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("checking existence of %s: %w", key, err)
	}
	return n > 0, nil
}
