// ABOUTME: Unit tests for Redis Streams consumer with XREADGROUP support
// ABOUTME: Tests consumer group creation, message reading, and acknowledgment

package redis

import (
	"context"
	"encoding/json"
	"errors"
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

func TestStreamConsumer_ReadSelfHealsOnNoGroup(t *testing.T) {
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
		Stream:        "heal_queue",
		ConsumerGroup: "workers",
		ConsumerName:  "worker-1",
		BlockTimeout:  100 * time.Millisecond,
	}

	consumer, err := NewStreamConsumer(client, cfg)
	if err != nil {
		t.Fatalf("NewStreamConsumer() error = %v", err)
	}

	ctx := context.Background()

	// Create group, publish a message, then destroy the stream.
	if err := consumer.EnsureGroup(ctx); err != nil {
		t.Fatalf("EnsureGroup() error = %v", err)
	}

	_, err = consumer.Publish(ctx, map[string]any{"data": "before-delete"})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	// Nuke the stream entirely; simulates FLUSHALL / key expiry.
	rdb := client.Redis()
	rdb.Del(ctx, consumer.StreamKey())

	// Publish a new message (recreates stream without the group).
	_, err = consumer.Publish(ctx, map[string]any{"data": "after-delete"})
	if err != nil {
		t.Fatalf("Publish() after delete error = %v", err)
	}

	// Read should self-heal: detect NOGROUP, recreate group, and succeed.
	messages, err := consumer.Read(ctx, 10)
	if err != nil {
		t.Fatalf("Read() after stream delete should self-heal, got error: %v", err)
	}

	// After self-healing with "$" start ID, we won't see old messages,
	// but subsequent publishes should work. Publish one more and read it.
	_, err = consumer.Publish(ctx, map[string]any{"data": "post-heal"})
	if err != nil {
		t.Fatalf("Publish() post-heal error = %v", err)
	}

	messages, err = consumer.Read(ctx, 10)
	if err != nil {
		t.Fatalf("Read() post-heal error = %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Read() post-heal got %d messages, want 1", len(messages))
	}

	if messages[0].Values["data"] != "post-heal" {
		t.Errorf("message data = %q, want %q", messages[0].Values["data"], "post-heal")
	}
}

func TestIsNoGroupError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nogroup error",
			err:  errors.New("NOGROUP No such key 'test:queue' or consumer group 'workers' in XREADGROUP with GROUP option"),
			want: true,
		},
		{
			name: "busygroup error",
			err:  errors.New("BUSYGROUP Consumer Group name already exists"),
			want: false,
		},
		{
			name: "generic error",
			err:  errors.New("connection refused"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isNoGroupError(tt.err)
			if got != tt.want {
				t.Errorf("isNoGroupError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

