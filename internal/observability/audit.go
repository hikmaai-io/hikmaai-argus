// ABOUTME: Audit logging system for security event tracking
// ABOUTME: Records scan requests, access denials, DB updates, and job operations

package observability

import (
	"context"
	"log/slog"
	"time"
)

// Audit event type constants.
const (
	EventTypeScan   = "SCAN"
	EventTypeAccess = "ACCESS"
	EventTypeUpdate = "UPDATE"
	EventTypeUpload = "UPLOAD"
)

// Audit action constants.
const (
	ActionCreate = "CREATE"
	ActionRead   = "READ"
	ActionDelete = "DELETE"
)

// Audit result constants.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultDenied  = "denied"
)

// AuditLogger provides structured audit logging for security events.
type AuditLogger struct {
	logger *slog.Logger
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(logger *slog.Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger,
	}
}

// LogScanRequest logs a scan request event.
func (a *AuditLogger) LogScanRequest(ctx context.Context, orgID, jobID, fileHash string) {
	correlationID := FromContext(ctx)

	a.logger.InfoContext(ctx, "audit_event",
		slog.String("event_type", EventTypeScan),
		slog.String("action", ActionCreate),
		slog.String("organization_id", orgID),
		slog.String("resource", jobID),
		slog.String("file_hash", fileHash),
		slog.String("result", ResultSuccess),
		slog.String("correlation_id", string(correlationID)),
		slog.Time("timestamp", time.Now().UTC()),
	)
}

// LogAccessDenied logs an access denial event.
func (a *AuditLogger) LogAccessDenied(ctx context.Context, orgID, resource, reason string) {
	correlationID := FromContext(ctx)

	a.logger.WarnContext(ctx, "audit_event",
		slog.String("event_type", EventTypeAccess),
		slog.String("action", ActionRead),
		slog.String("organization_id", orgID),
		slog.String("resource", resource),
		slog.String("result", ResultDenied),
		slog.String("reason", reason),
		slog.String("correlation_id", string(correlationID)),
		slog.Time("timestamp", time.Now().UTC()),
	)
}

// LogDBUpdate logs a database update event.
func (a *AuditLogger) LogDBUpdate(ctx context.Context, source string, success bool, details string) {
	correlationID := FromContext(ctx)

	result := ResultSuccess
	if !success {
		result = ResultFailure
	}

	a.logger.InfoContext(ctx, "audit_event",
		slog.String("event_type", EventTypeUpdate),
		slog.String("action", ActionCreate),
		slog.String("actor", "system"),
		slog.String("resource", source),
		slog.String("result", result),
		slog.String("details", details),
		slog.String("correlation_id", string(correlationID)),
		slog.Time("timestamp", time.Now().UTC()),
	)
}

// LogJobCancellation logs a job cancellation event.
func (a *AuditLogger) LogJobCancellation(ctx context.Context, jobID, reason string) {
	correlationID := FromContext(ctx)

	a.logger.InfoContext(ctx, "audit_event",
		slog.String("event_type", EventTypeScan),
		slog.String("action", ActionDelete),
		slog.String("resource", jobID),
		slog.String("result", ResultSuccess),
		slog.String("reason", reason),
		slog.String("correlation_id", string(correlationID)),
		slog.Time("timestamp", time.Now().UTC()),
	)
}

// LogFileUpload logs a file upload event.
func (a *AuditLogger) LogFileUpload(ctx context.Context, orgID, fileHash string, fileSize int64) {
	correlationID := FromContext(ctx)

	a.logger.InfoContext(ctx, "audit_event",
		slog.String("event_type", EventTypeUpload),
		slog.String("action", ActionCreate),
		slog.String("organization_id", orgID),
		slog.String("file_hash", fileHash),
		slog.Int64("file_size", fileSize),
		slog.String("result", ResultSuccess),
		slog.String("correlation_id", string(correlationID)),
		slog.Time("timestamp", time.Now().UTC()),
	)
}

// LogRateLimitViolation logs a rate limit violation event.
func (a *AuditLogger) LogRateLimitViolation(ctx context.Context, orgID, endpoint string, limit int) {
	correlationID := FromContext(ctx)

	a.logger.WarnContext(ctx, "audit_event",
		slog.String("event_type", EventTypeAccess),
		slog.String("action", ActionRead),
		slog.String("organization_id", orgID),
		slog.String("resource", endpoint),
		slog.String("result", ResultDenied),
		slog.String("reason", "rate_limit_exceeded"),
		slog.Int("limit", limit),
		slog.String("correlation_id", string(correlationID)),
		slog.Time("timestamp", time.Now().UTC()),
	)
}
