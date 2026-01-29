// ABOUTME: Unit tests for Redis Streams consumer with XREADGROUP support
// ABOUTME: Tests consumer group creation, message reading, and acknowledgment

package redis

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestNewStreamConsumer(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	cfg := StreamConsumerConfig{
		Stream:        "task_queue",
		ConsumerGroup: "workers",
		ConsumerName:  "worker-1",
		BlockTimeout:  time.Second,
	}

	consumer, err := NewStreamConsumer(client, cfg)
	if err != nil {
		t.Fatalf("NewStreamConsumer() error = %v", err)
	}

	if consumer == nil {
		t.Error("NewStreamConsumer() returned nil")
	}
}

func TestStreamConsumer_EnsureGroup(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	cfg := StreamConsumerConfig{
		Stream:        "task_queue",
		ConsumerGroup: "workers",
		ConsumerName:  "worker-1",
	}

	consumer, err := NewStreamConsumer(client, cfg)
	if err != nil {
		t.Fatalf("NewStreamConsumer() error = %v", err)
	}

	ctx := context.Background()

	// First call should create the group.
	if err := consumer.EnsureGroup(ctx); err != nil {
		t.Fatalf("EnsureGroup() first call error = %v", err)
	}

	// Second call should be idempotent.
	if err := consumer.EnsureGroup(ctx); err != nil {
		t.Errorf("EnsureGroup() second call error = %v", err)
	}
}

func TestStreamConsumer_ReadAndAck(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "argus:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	cfg := StreamConsumerConfig{
		Stream:        "task_queue",
		ConsumerGroup: "workers",
		ConsumerName:  "worker-1",
		BlockTimeout:  100 * time.Millisecond,
	}

	consumer, err := NewStreamConsumer(client, cfg)
	if err != nil {
		t.Fatalf("NewStreamConsumer() error = %v", err)
	}

	ctx := context.Background()

	// Ensure group exists.
	if err := consumer.EnsureGroup(ctx); err != nil {
		t.Fatalf("EnsureGroup() error = %v", err)
	}

	// Add a message to the stream using consumer's Publish method.
	testMsg := map[string]string{
		"job_id": "test-123",
		"action": "scan",
	}
	msgJSON, _ := json.Marshal(testMsg)

	_, err = consumer.Publish(ctx, map[string]any{"data": string(msgJSON)})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	// Read messages.
	messages, err := consumer.Read(ctx, 10)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Read() got %d messages, want 1", len(messages))
	}

	msg := messages[0]
	if msg.ID == "" {
		t.Error("message ID is empty")
	}

	data, ok := msg.Values["data"]
	if !ok {
		t.Fatal("message missing 'data' field")
	}

	if data != string(msgJSON) {
		t.Errorf("message data = %q, want %q", data, string(msgJSON))
	}

	// Acknowledge the message.
	if err := consumer.Ack(ctx, msg.ID); err != nil {
		t.Errorf("Ack() error = %v", err)
	}
}

func TestStreamConsumer_PrefixedStream(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "prod:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	cfg := StreamConsumerConfig{
		Stream:        "argus_task_queue",
		ConsumerGroup: "argus-workers",
		ConsumerName:  "argus-1",
	}

	consumer, err := NewStreamConsumer(client, cfg)
	if err != nil {
		t.Fatalf("NewStreamConsumer() error = %v", err)
	}

	// Verify the stream key is prefixed.
	want := "prod:argus_task_queue"
	got := consumer.StreamKey()
	if got != want {
		t.Errorf("StreamKey() = %q, want %q", got, want)
	}
}

func TestStreamConsumer_ReadTimeout(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)

	client, err := NewClient(Config{
		Addr:   mr.Addr(),
		Prefix: "test:",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	cfg := StreamConsumerConfig{
		Stream:        "empty_queue",
		ConsumerGroup: "workers",
		ConsumerName:  "worker-1",
		BlockTimeout:  50 * time.Millisecond,
	}

	consumer, err := NewStreamConsumer(client, cfg)
	if err != nil {
		t.Fatalf("NewStreamConsumer() error = %v", err)
	}

	ctx := context.Background()
	if err := consumer.EnsureGroup(ctx); err != nil {
		t.Fatalf("EnsureGroup() error = %v", err)
	}

	// Read from empty stream should return empty slice (not error).
	start := time.Now()
	messages, err := consumer.Read(ctx, 10)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	if len(messages) != 0 {
		t.Errorf("Read() got %d messages, want 0", len(messages))
	}

	// Should have blocked for approximately BlockTimeout.
	if elapsed < 40*time.Millisecond {
		t.Errorf("Read() returned too quickly: %v", elapsed)
	}
}

