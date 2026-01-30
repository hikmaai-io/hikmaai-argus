// ABOUTME: Argus worker orchestrator for processing scan tasks from Redis
// ABOUTME: Downloads skills from GCS, runs scanners, updates state, publishes completion

package argus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/gcs"
	"github.com/hikmaai-io/hikmaai-argus/internal/redis"
	"github.com/hikmaai-io/hikmaai-argus/internal/trivy"
	goredis "github.com/redis/go-redis/v9"
)

// WorkerConfig holds configuration for the Argus worker.
type WorkerConfig struct {
	// TaskQueue is the Redis stream name for incoming tasks.
	TaskQueue string

	// ConsumerGroup is the consumer group name for scaling.
	ConsumerGroup string

	// ConsumerName is this instance's consumer name.
	ConsumerName string

	// CompletionPrefix is the prefix for completion signal streams.
	CompletionPrefix string

	// CancelPrefix is the prefix for cancellation Pub/Sub channels.
	CancelPrefix string

	// Workers is the number of concurrent processing goroutines.
	Workers int

	// DefaultTimeout for scan operations.
	DefaultTimeout time.Duration

	// MaxRetries before giving up on a task.
	MaxRetries int

	// CleanupOnComplete removes temp files after scan.
	CleanupOnComplete bool

	// StateTTL is the TTL for job state entries.
	StateTTL time.Duration
}

// Validate checks that required fields are set and applies defaults.
func (c *WorkerConfig) Validate() error {
	if c.TaskQueue == "" {
		return errors.New("task_queue is required")
	}
	if c.ConsumerGroup == "" {
		return errors.New("consumer_group is required")
	}
	if c.ConsumerName == "" {
		return errors.New("consumer_name is required")
	}
	if c.CompletionPrefix == "" {
		c.CompletionPrefix = "argus_completion"
	}
	if c.CancelPrefix == "" {
		c.CancelPrefix = "argus_cancel"
	}
	if c.Workers <= 0 {
		c.Workers = 2
	}
	if c.DefaultTimeout <= 0 {
		c.DefaultTimeout = 15 * time.Minute
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = 3
	}
	if c.StateTTL <= 0 {
		c.StateTTL = 7 * 24 * time.Hour // 7 days
	}
	return nil
}

// TaskProcessor processes a single task.
type TaskProcessor interface {
	Process(ctx context.Context, msg *TaskMessage) (*ArgusResults, error)
}

// Worker processes scan tasks from Redis.
type Worker struct {
	config        WorkerConfig
	redisClient   *redis.Client
	consumer      *redis.StreamConsumer
	stateManager  *redis.StateManager
	gcsClient     *gcs.Client
	runner        *Runner
	logger        *slog.Logger

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewWorker creates a new Argus worker.
func NewWorker(
	cfg WorkerConfig,
	redisClient *redis.Client,
	gcsClient *gcs.Client,
	runner *Runner,
	logger *slog.Logger,
) (*Worker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create stream consumer.
	consumer, err := redis.NewStreamConsumer(redisClient, redis.StreamConsumerConfig{
		Stream:        cfg.TaskQueue,
		ConsumerGroup: cfg.ConsumerGroup,
		ConsumerName:  cfg.ConsumerName,
		BlockTimeout:  5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("creating stream consumer: %w", err)
	}

	// Create state manager.
	stateManager := redis.NewStateManager(redisClient, redis.StateManagerConfig{
		KeyPrefix:  "job_state:",
		DefaultTTL: cfg.StateTTL,
	})

	if logger == nil {
		logger = slog.Default()
	}

	return &Worker{
		config:       cfg,
		redisClient:  redisClient,
		consumer:     consumer,
		stateManager: stateManager,
		gcsClient:    gcsClient,
		runner:       runner,
		logger:       logger,
		stopCh:       make(chan struct{}),
	}, nil
}

// Start begins processing tasks.
func (w *Worker) Start(ctx context.Context) error {
	// Ensure consumer group exists.
	if err := w.consumer.EnsureGroup(ctx); err != nil {
		return fmt.Errorf("ensuring consumer group: %w", err)
	}

	w.logger.Info("argus worker starting",
		slog.String("queue", w.config.TaskQueue),
		slog.String("group", w.config.ConsumerGroup),
		slog.String("name", w.config.ConsumerName),
		slog.Int("workers", w.config.Workers),
	)

	// Start worker goroutines.
	for i := 0; i < w.config.Workers; i++ {
		w.wg.Add(1)
		go w.processLoop(ctx, i)
	}

	return nil
}

// Stop signals the worker to stop processing.
func (w *Worker) Stop() {
	close(w.stopCh)
	w.wg.Wait()
	w.logger.Info("argus worker stopped")
}

// processLoop is the main processing loop for a worker goroutine.
func (w *Worker) processLoop(ctx context.Context, workerID int) {
	defer w.wg.Done()

	logger := w.logger.With(slog.Int("worker_id", workerID))
	logger.Debug("worker started")

	for {
		select {
		case <-w.stopCh:
			logger.Debug("worker stopping")
			return
		case <-ctx.Done():
			logger.Debug("context cancelled")
			return
		default:
		}

		// Read messages.
		messages, err := w.consumer.Read(ctx, 1)
		if err != nil {
			logger.Error("reading from stream", slog.Any("error", err))
			continue
		}

		for _, msg := range messages {
			w.processMessage(ctx, logger, msg)
		}
	}
}

// processMessage handles a single message from the stream.
func (w *Worker) processMessage(ctx context.Context, logger *slog.Logger, msg redis.StreamMessage) {
	// Parse the task message.
	data, ok := msg.Values["data"]
	if !ok {
		logger.Error("message missing data field", slog.String("msg_id", msg.ID))
		_ = w.consumer.Ack(ctx, msg.ID)
		return
	}

	task, err := ParseTaskMessage(data)
	if err != nil {
		logger.Error("parsing task message", slog.Any("error", err), slog.String("msg_id", msg.ID))
		_ = w.consumer.Ack(ctx, msg.ID)
		return
	}

	logger = logger.With(
		slog.String("job_id", task.JobID),
		slog.String("org_id", task.OrganizationID),
	)

	// Acknowledge immediately to prevent redelivery during long processing.
	if err := w.consumer.Ack(ctx, msg.ID); err != nil {
		logger.Error("acknowledging message", slog.Any("error", err))
	}

	// Process the task.
	w.processTask(ctx, logger, task)
}

// processTask handles the full scan workflow.
func (w *Worker) processTask(ctx context.Context, logger *slog.Logger, task *TaskMessage) {
	startTime := time.Now()

	// Create context with timeout.
	timeout := task.Timeout()
	if timeout == 0 {
		timeout = w.config.DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Initialize state.
	if err := w.initializeState(ctx, task); err != nil {
		logger.Error("initializing state", slog.Any("error", err))
		w.publishCompletion(ctx, task.JobID, "failed", nil)
		return
	}

	// Validate organization path.
	if !gcs.ValidateOrganizationPath(task.GCSURI, task.OrganizationID) {
		logger.Error("organization path validation failed",
			slog.String("gcs_uri", task.GCSURI),
		)
		w.failTask(ctx, task.JobID, "invalid GCS path for organization")
		return
	}

	// Download from GCS.
	logger.Info("downloading skill from GCS", slog.String("gcs_uri", task.GCSURI))
	downloadResult, err := w.gcsClient.DownloadFromURI(ctx, task.GCSURI, task.JobID)
	if err != nil {
		logger.Error("downloading from GCS", slog.Any("error", err))
		w.failTask(ctx, task.JobID, fmt.Sprintf("download failed: %v", err))
		return
	}

	// Extract if archive.
	scanPath := downloadResult.LocalPath
	if isArchive(scanPath) {
		extractDir, err := trivy.ExtractArchive(scanPath)
		if err != nil {
			logger.Error("extracting archive", slog.Any("error", err))
			w.failTask(ctx, task.JobID, fmt.Sprintf("extraction failed: %v", err))
			return
		}
		scanPath = extractDir
		defer func() {
			if w.config.CleanupOnComplete {
				_ = os.RemoveAll(extractDir)
			}
		}()
	}

	// Run scanners.
	logger.Info("running scanners", slog.Any("scanners", task.Scanners))
	results, err := w.runScanners(ctx, logger, task, scanPath)
	if err != nil {
		logger.Error("running scanners", slog.Any("error", err))
		w.failTask(ctx, task.JobID, fmt.Sprintf("scan failed: %v", err))
		return
	}

	// Update final state.
	if err := w.updateFinalState(ctx, task.JobID, results); err != nil {
		logger.Error("updating final state", slog.Any("error", err))
	}

	// Publish completion.
	status := "completed"
	if results.HasErrors() {
		status = "partial"
	}
	w.publishCompletion(ctx, task.JobID, status, results)

	// Cleanup.
	if w.config.CleanupOnComplete {
		_ = w.gcsClient.CleanupJobDir(task.JobID)
	}

	elapsed := time.Since(startTime)
	logger.Info("task completed",
		slog.String("status", status),
		slog.Duration("duration", elapsed),
	)
}

// initializeState sets up the initial job state in Redis.
func (w *Worker) initializeState(ctx context.Context, task *TaskMessage) error {
	status := InitialArgusStatus(task.Scanners)
	statusJSON, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("marshaling status: %w", err)
	}

	fields := map[string]string{
		"argus_status": string(statusJSON),
		"started_at":   time.Now().UTC().Format(time.RFC3339),
	}

	return w.stateManager.InitState(ctx, task.JobID, fields)
}

// runScanners executes the requested scanners with state updates.
func (w *Worker) runScanners(ctx context.Context, logger *slog.Logger, task *TaskMessage, path string) (*ArgusResults, error) {
	results := &ArgusResults{
		Errors: make(map[string]string),
	}

	// Run Trivy.
	if task.HasScanner(ScannerTrivy) {
		w.updateScannerStatus(ctx, task.JobID, "trivy", StatusRunning)

		trivyResult, err := w.runner.RunTrivy(ctx, path)
		if err != nil {
			logger.Error("trivy scan failed", slog.Any("error", err))
			results.Errors["trivy"] = err.Error()
			w.updateScannerStatus(ctx, task.JobID, "trivy", StatusFailed)
		} else {
			results.Trivy = trivyResult
			w.updateScannerStatus(ctx, task.JobID, "trivy", StatusCompleted)
			w.updateScannerResults(ctx, task.JobID, "trivy", trivyResult)
		}
	}

	// Run ClamAV.
	if task.HasScanner(ScannerClamAV) {
		w.updateScannerStatus(ctx, task.JobID, "clamav", StatusRunning)

		clamResult, err := w.runner.RunClamAV(ctx, path)
		if err != nil {
			logger.Error("clamav scan failed", slog.Any("error", err))
			results.Errors["clamav"] = err.Error()
			w.updateScannerStatus(ctx, task.JobID, "clamav", StatusFailed)
		} else {
			results.ClamAV = clamResult
			w.updateScannerStatus(ctx, task.JobID, "clamav", StatusCompleted)
			w.updateScannerResults(ctx, task.JobID, "clamav", clamResult)
		}
	}

	// Clear errors if empty.
	if len(results.Errors) == 0 {
		results.Errors = nil
	}

	return results, nil
}

// updateScannerStatus updates a single scanner's status in Redis.
func (w *Worker) updateScannerStatus(ctx context.Context, jobID, scanner string, status ScannerStatus) {
	field := scanner + "_status"
	if err := w.stateManager.SetField(ctx, jobID, field, string(status)); err != nil {
		w.logger.Error("updating scanner status",
			slog.String("job_id", jobID),
			slog.String("scanner", scanner),
			slog.Any("error", err),
		)
	}
}

// updateScannerResults stores scanner results in Redis.
func (w *Worker) updateScannerResults(ctx context.Context, jobID, scanner string, results any) {
	field := scanner + "_results"
	if err := w.stateManager.SetJSON(ctx, jobID, field, results); err != nil {
		w.logger.Error("updating scanner results",
			slog.String("job_id", jobID),
			slog.String("scanner", scanner),
			slog.Any("error", err),
		)
	}
}

// updateFinalState updates the job state with completion info.
func (w *Worker) updateFinalState(ctx context.Context, jobID string, results *ArgusResults) error {
	fields := map[string]string{
		"completed_at": time.Now().UTC().Format(time.RFC3339),
	}

	if results.HasErrors() {
		errJSON, _ := json.Marshal(results.Errors)
		fields["errors"] = string(errJSON)
	}

	return w.stateManager.SetFields(ctx, jobID, fields)
}

// failTask marks a task as failed and publishes completion.
func (w *Worker) failTask(ctx context.Context, jobID, errMsg string) {
	fields := map[string]string{
		"error":        errMsg,
		"completed_at": time.Now().UTC().Format(time.RFC3339),
	}
	_ = w.stateManager.SetFields(ctx, jobID, fields)

	w.publishCompletion(ctx, jobID, "failed", nil)
}

// cancelTask marks a task as cancelled and publishes completion.
func (w *Worker) cancelTask(ctx context.Context, jobID string) {
	fields := map[string]string{
		"cancelled":    "true",
		"cancelled_at": time.Now().UTC().Format(time.RFC3339),
	}
	_ = w.stateManager.SetFields(ctx, jobID, fields)

	// Set both scanner statuses to cancelled.
	_ = w.stateManager.SetField(ctx, jobID, "trivy_status", string(StatusCancelled))
	_ = w.stateManager.SetField(ctx, jobID, "clamav_status", string(StatusCancelled))

	w.publishCompletion(ctx, jobID, "cancelled", nil)

	w.logger.Info("task cancelled",
		slog.String("job_id", jobID),
	)
}

// publishCompletion sends a completion signal to Redis.
func (w *Worker) publishCompletion(ctx context.Context, jobID, status string, results *ArgusResults) {
	signal := CompletionSignal{
		JobID:       jobID,
		Status:      status,
		CompletedAt: time.Now().UTC(),
		Results:     results,
	}

	signalJSON, err := json.Marshal(signal)
	if err != nil {
		w.logger.Error("marshaling completion signal", slog.Any("error", err))
		return
	}

	// Publish to completion stream.
	streamKey := w.config.CompletionPrefix + ":" + jobID
	_, err = w.redisClient.Redis().XAdd(ctx, &goredis.XAddArgs{
		Stream: w.redisClient.PrefixedKey(streamKey),
		Values: map[string]any{"data": string(signalJSON)},
	}).Result()

	if err != nil {
		w.logger.Error("publishing completion signal",
			slog.String("job_id", jobID),
			slog.Any("error", err),
		)
	}
}

// ParseTaskMessage parses a JSON task message.
func ParseTaskMessage(data string) (*TaskMessage, error) {
	if data == "" {
		return nil, errors.New("empty message data")
	}

	var msg TaskMessage
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil, fmt.Errorf("unmarshaling message: %w", err)
	}

	if err := msg.Validate(); err != nil {
		return nil, fmt.Errorf("validating message: %w", err)
	}

	return &msg, nil
}

// InitialArgusStatus creates the initial status for requested scanners.
func InitialArgusStatus(scanners []string) ArgusStatus {
	status := ArgusStatus{}

	for _, s := range scanners {
		switch ScannerName(s) {
		case ScannerTrivy:
			status.Trivy = StatusPending
		case ScannerClamAV:
			status.ClamAV = StatusPending
		}
	}

	return status
}

// isArchive checks if a file is an archive based on extension.
func isArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".zip" || ext == ".tar" || ext == ".gz" || ext == ".tgz"
}

// CancelChannelName returns the Redis Pub/Sub channel name for cancellation signals.
func CancelChannelName(prefix, jobID string) string {
	return prefix + ":" + jobID
}

// CancellationListener handles cancellation signal monitoring.
type CancellationListener struct {
	cancelledCh chan struct{}
	stopOnce    sync.Once
}

// NewCancellationListener creates a new cancellation listener.
func NewCancellationListener() *CancellationListener {
	return &CancellationListener{
		cancelledCh: make(chan struct{}),
	}
}

// Done returns a channel that is closed when cancellation is received.
func (c *CancellationListener) Done() <-chan struct{} {
	return c.cancelledCh
}

// Stop stops the listener and closes the done channel.
func (c *CancellationListener) Stop() {
	c.stopOnce.Do(func() {
		close(c.cancelledCh)
	})
}

// listenForCancel subscribes to the cancellation Pub/Sub channel and signals
// when a cancellation message is received.
func (w *Worker) listenForCancel(ctx context.Context, jobID string) *CancellationListener {
	listener := NewCancellationListener()

	channelName := CancelChannelName(w.config.CancelPrefix, jobID)
	prefixedChannel := w.redisClient.PrefixedKey(channelName)

	go func() {
		pubsub := w.redisClient.Redis().Subscribe(ctx, prefixedChannel)
		defer pubsub.Close()

		ch := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				if msg != nil {
					w.logger.Info("received cancellation signal",
						slog.String("job_id", jobID),
						slog.String("channel", channelName),
					)
					listener.Stop()
					return
				}
			}
		}
	}()

	return listener
}
