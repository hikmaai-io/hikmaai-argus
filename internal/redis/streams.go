// ABOUTME: Redis Streams consumer with XREADGROUP support for distributed task processing
// ABOUTME: Supports consumer groups, message acknowledgment, and configurable key prefix

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// StreamConsumerConfig holds configuration for a Redis Streams consumer.
type StreamConsumerConfig struct {
	// Stream is the stream name (without prefix).
	Stream string

	// ConsumerGroup is the consumer group name.
	ConsumerGroup string

	// ConsumerName is this consumer's unique name within the group.
	ConsumerName string

	// BlockTimeout is how long to block waiting for messages.
	// Zero means block indefinitely.
	BlockTimeout time.Duration

	// StartID is the message ID to start reading from.
	// Default ">" reads only new messages; "0" reads pending messages.
	StartID string
}

// StreamMessage represents a message read from a Redis Stream.
type StreamMessage struct {
	// ID is the message ID (e.g., "1234567890123-0").
	ID string

	// Values contains the message fields.
	Values map[string]string
}

// StreamConsumer reads messages from a Redis Stream using consumer groups.
type StreamConsumer struct {
	client        *Client
	streamKey     string
	consumerGroup string
	consumerName  string
	blockTimeout  time.Duration
	startID       string
}

// NewStreamConsumer creates a new stream consumer with the given configuration.
func NewStreamConsumer(client *Client, cfg StreamConsumerConfig) (*StreamConsumer, error) {
	if client == nil {
		return nil, errors.New("client is required")
	}
	if cfg.Stream == "" {
		return nil, errors.New("stream name is required")
	}
	if cfg.ConsumerGroup == "" {
		return nil, errors.New("consumer group is required")
	}
	if cfg.ConsumerName == "" {
		return nil, errors.New("consumer name is required")
	}

	startID := cfg.StartID
	if startID == "" {
		startID = ">" // Default: only new messages.
	}

	return &StreamConsumer{
		client:        client,
		streamKey:     client.PrefixedKey(cfg.Stream),
		consumerGroup: cfg.ConsumerGroup,
		consumerName:  cfg.ConsumerName,
		blockTimeout:  cfg.BlockTimeout,
		startID:       startID,
	}, nil
}

// StreamKey returns the full prefixed stream key.
func (c *StreamConsumer) StreamKey() string {
	return c.streamKey
}

// EnsureGroup creates the consumer group if it doesn't exist.
// This is idempotent; calling it multiple times is safe.
func (c *StreamConsumer) EnsureGroup(ctx context.Context) error {
	rdb := c.client.Redis()

	// XGROUP CREATE stream group $ MKSTREAM
	// $ means start from the latest message; MKSTREAM creates the stream if needed.
	err := rdb.XGroupCreateMkStream(ctx, c.streamKey, c.consumerGroup, "$").Err()
	if err != nil {
		// BUSYGROUP means the group already exists; that's OK.
		if isBusyGroupError(err) {
			return nil
		}
		return fmt.Errorf("creating consumer group %s on %s: %w", c.consumerGroup, c.streamKey, err)
	}

	return nil
}

// Read reads up to count messages from the stream.
// Returns an empty slice if no messages are available within BlockTimeout.
func (c *StreamConsumer) Read(ctx context.Context, count int64) ([]StreamMessage, error) {
	rdb := c.client.Redis()

	streams, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    c.consumerGroup,
		Consumer: c.consumerName,
		Streams:  []string{c.streamKey, c.startID},
		Count:    count,
		Block:    c.blockTimeout,
	}).Result()

	if err != nil {
		// redis.Nil means timeout with no messages; return empty slice.
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading from stream %s: %w", c.streamKey, err)
	}

	// Convert to our message type.
	var messages []StreamMessage
	for _, stream := range streams {
		for _, msg := range stream.Messages {
			values := make(map[string]string, len(msg.Values))
			for k, v := range msg.Values {
				if s, ok := v.(string); ok {
					values[k] = s
				}
			}
			messages = append(messages, StreamMessage{
				ID:     msg.ID,
				Values: values,
			})
		}
	}

	return messages, nil
}

// Ack acknowledges a message, removing it from the pending entries list.
func (c *StreamConsumer) Ack(ctx context.Context, messageID string) error {
	rdb := c.client.Redis()

	if err := rdb.XAck(ctx, c.streamKey, c.consumerGroup, messageID).Err(); err != nil {
		return fmt.Errorf("acknowledging message %s: %w", messageID, err)
	}

	return nil
}

// AckMany acknowledges multiple messages in a single call.
func (c *StreamConsumer) AckMany(ctx context.Context, messageIDs ...string) error {
	if len(messageIDs) == 0 {
		return nil
	}

	rdb := c.client.Redis()

	if err := rdb.XAck(ctx, c.streamKey, c.consumerGroup, messageIDs...).Err(); err != nil {
		return fmt.Errorf("acknowledging %d messages: %w", len(messageIDs), err)
	}

	return nil
}

// Publish adds a message to the stream.
// Returns the message ID assigned by Redis.
func (c *StreamConsumer) Publish(ctx context.Context, values map[string]any) (string, error) {
	rdb := c.client.Redis()

	id, err := rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: c.streamKey,
		Values: values,
	}).Result()

	if err != nil {
		return "", fmt.Errorf("publishing to stream %s: %w", c.streamKey, err)
	}

	return id, nil
}

// isBusyGroupError checks if the error is BUSYGROUP (group already exists).
func isBusyGroupError(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "BUSYGROUP Consumer Group name already exists"
}
