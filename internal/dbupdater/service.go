// ABOUTME: DB update service orchestrating all scanner database updaters
// ABOUTME: Manages lifecycle, scheduling, retry logic, and status tracking

package dbupdater

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DBUpdateServiceConfig configures the DB update service.
type DBUpdateServiceConfig struct {
	// Coordinator manages scan/update coordination.
	Coordinator *ScanCoordinator

	// Logger for structured logging.
	Logger *slog.Logger

	// RetryConfig configures retry behavior for failed updates.
	RetryConfig BackoffConfig

	// RunInitialUpdate triggers an update immediately on Start.
	RunInitialUpdate bool
}

// updaterEntry holds an updater and its configuration.
type updaterEntry struct {
	updater  Updater
	interval time.Duration
	trigger  chan struct{}
}

// DBUpdateService orchestrates database updates for all registered updaters.
type DBUpdateService struct {
	config   DBUpdateServiceConfig
	status   *StatusTracker
	updaters map[string]*updaterEntry

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewDBUpdateService creates a new DB update service.
func NewDBUpdateService(config DBUpdateServiceConfig) *DBUpdateService {
	if config.Coordinator == nil {
		config.Coordinator = NewScanCoordinator()
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	return &DBUpdateService{
		config:   config,
		status:   NewStatusTracker(),
		updaters: make(map[string]*updaterEntry),
	}
}

// RegisterUpdater registers an updater with the service.
func (s *DBUpdateService) RegisterUpdater(updater Updater, interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := updater.Name()
	s.updaters[name] = &updaterEntry{
		updater:  updater,
		interval: interval,
		trigger:  make(chan struct{}, 1),
	}
	s.status.Register(name)

	// Set initial version and ready status.
	info := updater.GetVersionInfo()
	s.status.SetVersion(name, info)
	s.status.SetReady(name, updater.IsReady())
}

// Start starts the update service.
func (s *DBUpdateService) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("service already running")
	}

	ctx, s.cancel = context.WithCancel(ctx)
	s.running = true
	s.mu.Unlock()

	// Start worker goroutines for each updater.
	for name, entry := range s.updaters {
		s.wg.Add(1)
		go s.runUpdaterWorker(ctx, name, entry)
	}

	s.config.Logger.Info("db update service started",
		slog.Int("updaters", len(s.updaters)),
	)

	return nil
}

// Stop stops the update service.
func (s *DBUpdateService) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.cancel()
	s.running = false
	s.mu.Unlock()

	// Wait for all workers to finish.
	s.wg.Wait()

	s.config.Logger.Info("db update service stopped")
}

// IsRunning returns true if the service is running.
func (s *DBUpdateService) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// TriggerUpdate manually triggers an update for a specific updater.
func (s *DBUpdateService) TriggerUpdate(ctx context.Context, name string) error {
	s.mu.Lock()
	entry, ok := s.updaters[name]
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("updater %q not found", name)
	}

	// Non-blocking send to trigger channel.
	select {
	case entry.trigger <- struct{}{}:
		return nil
	default:
		// Already triggered, pending update.
		return nil
	}
}

// GetStatus returns the status of all updaters.
func (s *DBUpdateService) GetStatus() map[string]*UpdaterStatus {
	return s.status.GetAll()
}

// Coordinator returns the scan coordinator.
func (s *DBUpdateService) Coordinator() *ScanCoordinator {
	return s.config.Coordinator
}

// runUpdaterWorker runs the update loop for a single updater.
func (s *DBUpdateService) runUpdaterWorker(ctx context.Context, name string, entry *updaterEntry) {
	defer s.wg.Done()

	ticker := time.NewTicker(entry.interval)
	defer ticker.Stop()

	logger := s.config.Logger.With(slog.String("updater", name))

	// Schedule next update.
	s.status.SetNextScheduled(name, time.Now().Add(entry.interval))

	// Run initial update if configured.
	if s.config.RunInitialUpdate {
		s.executeUpdate(ctx, name, entry, logger)
	}

	for {
		select {
		case <-ctx.Done():
			logger.Debug("updater worker stopped")
			return

		case <-ticker.C:
			s.executeUpdate(ctx, name, entry, logger)
			s.status.SetNextScheduled(name, time.Now().Add(entry.interval))

		case <-entry.trigger:
			logger.Info("manual update triggered")
			s.executeUpdate(ctx, name, entry, logger)
		}
	}
}

// executeUpdate performs the update with retry logic.
func (s *DBUpdateService) executeUpdate(ctx context.Context, name string, entry *updaterEntry, logger *slog.Logger) {
	// Acquire update lock.
	release, err := s.config.Coordinator.AcquireForUpdate(ctx)
	if err != nil {
		logger.Warn("failed to acquire update lock", slog.String("error", err.Error()))
		return
	}
	defer release()

	s.status.SetStatus(name, StatusUpdating)
	logger.Info("starting update")

	backoff := NewBackoff(s.config.RetryConfig)

	for {
		result, err := entry.updater.Update(ctx)

		if err == nil && result.Success {
			// Success.
			s.status.SetStatus(name, StatusIdle)
			s.status.SetLastUpdate(name, time.Now())
			s.status.SetError(name, "")
			s.status.SetVersion(name, entry.updater.GetVersionInfo())
			s.status.SetReady(name, entry.updater.IsReady())

			logger.Info("update completed",
				slog.Int("downloaded", result.Downloaded),
				slog.Int("skipped", result.Skipped),
				slog.Duration("duration", result.Duration),
			)
			return
		}

		// Handle failure.
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		} else if result != nil && result.Error != "" {
			errMsg = result.Error
		}

		s.status.SetError(name, errMsg)
		logger.Warn("update failed",
			slog.String("error", errMsg),
			slog.Int("attempt", backoff.Attempts()+1),
		)

		// Get next retry delay.
		delay, ok := backoff.NextDelay()
		if !ok {
			// Max retries exceeded.
			s.status.SetStatus(name, StatusFailed)
			logger.Error("update failed after max retries",
				slog.Int("attempts", backoff.Attempts()),
			)
			return
		}

		// Wait before retry.
		select {
		case <-ctx.Done():
			s.status.SetStatus(name, StatusFailed)
			return
		case <-time.After(delay):
			logger.Debug("retrying update", slog.Duration("delay", delay))
		}
	}
}
