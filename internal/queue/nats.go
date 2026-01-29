// ABOUTME: NATS client wrapper for queue subscriptions
// ABOUTME: Handles connection, subscription with queue groups, and graceful shutdown

package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/hikmaai-io/hikma-av/internal/observability"
)

// NATSConfig holds NATS connection configuration.
type NATSConfig struct {
	// NATS server URL.
	URL string

	// Subject to subscribe to for scan requests.
	Subject string

	// Queue group name for load balancing.
	QueueGroup string

	// Connection name for identification.
	Name string

	// Reconnect settings.
	MaxReconnects int
	ReconnectWait time.Duration

	// Request timeout.
	Timeout time.Duration
}

// DefaultNATSConfig returns a configuration with sensible defaults.
func DefaultNATSConfig() NATSConfig {
	return NATSConfig{
		URL:           "nats://localhost:4222",
		Subject:       "hikma.av.scan",
		QueueGroup:    "av-workers",
		Name:          "hikma-av",
		MaxReconnects: -1, // Unlimited.
		ReconnectWait: 2 * time.Second,
		Timeout:       5 * time.Second,
	}
}

// Client wraps the NATS connection and subscription.
type Client struct {
	conn    *nats.Conn
	sub     *nats.Subscription
	handler *Handler
	config  NATSConfig
	logger  *slog.Logger
}

// NewClient creates a new NATS client with the given configuration.
func NewClient(cfg NATSConfig, handler *Handler, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		handler: handler,
		config:  cfg,
		logger:  logger,
	}, nil
}

// Connect establishes the NATS connection.
func (c *Client) Connect(ctx context.Context) error {
	opts := []nats.Option{
		nats.Name(c.config.Name),
		nats.MaxReconnects(c.config.MaxReconnects),
		nats.ReconnectWait(c.config.ReconnectWait),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			c.logger.Warn("NATS disconnected", slog.Any("error", err))
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			c.logger.Info("NATS reconnected", slog.String("url", nc.ConnectedUrl()))
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			c.logger.Info("NATS connection closed")
		}),
		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
			c.logger.Error("NATS error",
				slog.Any("error", err),
				slog.String("subject", sub.Subject),
			)
		}),
	}

	conn, err := nats.Connect(c.config.URL, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}

	c.conn = conn
	c.logger.Info("connected to NATS",
		slog.String("url", conn.ConnectedUrl()),
		slog.String("server_id", conn.ConnectedServerId()),
	)

	return nil
}

// Subscribe starts listening for scan requests.
func (c *Client) Subscribe(ctx context.Context) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to NATS")
	}

	sub, err := c.conn.QueueSubscribe(c.config.Subject, c.config.QueueGroup, func(msg *nats.Msg) {
		c.handleMessage(ctx, msg)
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	c.sub = sub
	c.logger.Info("subscribed to NATS",
		slog.String("subject", c.config.Subject),
		slog.String("queue", c.config.QueueGroup),
	)

	return nil
}

// handleMessage processes an incoming NATS message.
func (c *Client) handleMessage(ctx context.Context, msg *nats.Msg) {
	// Start a span for tracing.
	ctx, span := observability.StartSpan(ctx, "nats.handle_message")
	defer span.End()

	start := time.Now()

	// Parse request.
	var req ScanRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		c.logger.Error("failed to parse scan request",
			slog.Any("error", err),
			slog.String("data", string(msg.Data)),
		)
		c.replyError(msg, "", "invalid request format: "+err.Error())
		return
	}

	// Process request.
	resp := c.handler.ProcessRequest(ctx, req)

	// Send reply if requested.
	if msg.Reply != "" {
		respData, err := json.Marshal(resp)
		if err != nil {
			c.logger.Error("failed to marshal response",
				slog.Any("error", err),
				slog.String("request_id", req.RequestID),
			)
			return
		}

		if err := msg.Respond(respData); err != nil {
			c.logger.Error("failed to send reply",
				slog.Any("error", err),
				slog.String("request_id", req.RequestID),
			)
			return
		}
	}

	// Log the request.
	elapsed := time.Since(start)
	c.logger.Info("processed scan request",
		slog.String("request_id", req.RequestID),
		slog.String("hash", truncateHash(req.Hash)),
		slog.String("status", resp.Status),
		slog.Duration("duration", elapsed),
	)
}

// replyError sends an error response.
func (c *Client) replyError(msg *nats.Msg, requestID, errMsg string) {
	if msg.Reply == "" {
		return
	}

	resp := ScanResponse{
		RequestID: requestID,
		Status:    "error",
		Error:     errMsg,
		ScannedAt: time.Now().UTC(),
	}

	respData, err := json.Marshal(resp)
	if err != nil {
		c.logger.Error("failed to marshal error response", slog.Any("error", err))
		return
	}

	if err := msg.Respond(respData); err != nil {
		c.logger.Error("failed to send error reply", slog.Any("error", err))
	}
}

// Close closes the NATS connection.
func (c *Client) Close() error {
	if c.sub != nil {
		if err := c.sub.Unsubscribe(); err != nil {
			c.logger.Warn("failed to unsubscribe", slog.Any("error", err))
		}
	}

	if c.conn != nil {
		c.conn.Close()
	}

	return nil
}

// IsConnected returns true if connected to NATS.
func (c *Client) IsConnected() bool {
	return c.conn != nil && c.conn.IsConnected()
}

// truncateHash returns a truncated hash for logging.
func truncateHash(hash string) string {
	if len(hash) > 16 {
		return hash[:8] + "..." + hash[len(hash)-8:]
	}
	return hash
}
