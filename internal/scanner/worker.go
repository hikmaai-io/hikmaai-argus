// ABOUTME: Background scan worker for processing async scan jobs
// ABOUTME: Pulls jobs from queue, executes scans, caches results, persists malware

package scanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/hikmaai-io/hikmaai-argus/internal/engine"
	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

// WorkerConfig holds configuration for the scan worker.
type WorkerConfig struct {
	// Scanner for file scanning.
	Scanner *ClamAVScanner

	// JobStore for job persistence.
	JobStore *engine.JobStore

	// ScanCache for caching results.
	ScanCache *engine.ScanCache

	// SignatureEngine for persisting malware detections (optional).
	SignatureEngine *engine.Engine

	// Concurrency is the number of concurrent workers.
	Concurrency int
}

// Worker processes scan jobs asynchronously.
type Worker struct {
	config WorkerConfig

	// Job queue for pending scans.
	jobQueue chan *scanJob
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopCh   chan struct{}
}

// scanJob represents a job with its file path.
type scanJob struct {
	jobID    string
	filePath string
}

// NewWorker creates a new scan worker.
func NewWorker(cfg WorkerConfig) *Worker {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2
	}

	return &Worker{
		config:   cfg,
		jobQueue: make(chan *scanJob, 100),
		stopCh:   make(chan struct{}),
	}
}

// Start begins processing jobs with the configured concurrency.
func (w *Worker) Start(ctx context.Context) {
	for i := 0; i < w.config.Concurrency; i++ {
		w.wg.Add(1)
		go w.workerLoop(ctx)
	}
}

// Stop gracefully stops all workers.
func (w *Worker) Stop() {
	w.stopOnce.Do(func() {
		close(w.stopCh)
		close(w.jobQueue)
	})
	w.wg.Wait()
}

// Submit adds a job to the queue for processing.
func (w *Worker) Submit(jobID, filePath string) error {
	select {
	case w.jobQueue <- &scanJob{jobID: jobID, filePath: filePath}:
		return nil
	case <-w.stopCh:
		return fmt.Errorf("worker stopped")
	default:
		return fmt.Errorf("job queue full")
	}
}

// workerLoop processes jobs from the queue.
func (w *Worker) workerLoop(ctx context.Context) {
	defer w.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case job, ok := <-w.jobQueue:
			if !ok {
				return
			}
			if err := w.ProcessJob(ctx, job.jobID, job.filePath); err != nil {
				// Log error but continue processing.
				fmt.Printf("Error processing job %s: %v\n", job.jobID, err)
			}
		}
	}
}

// ProcessJob processes a single job synchronously.
func (w *Worker) ProcessJob(ctx context.Context, jobID, filePath string) error {
	// Get job from store.
	job, err := w.config.JobStore.Get(ctx, jobID)
	if err != nil {
		return fmt.Errorf("getting job: %w", err)
	}
	if job == nil {
		return fmt.Errorf("job not found: %s", jobID)
	}

	// Check cache first.
	if w.config.ScanCache != nil {
		cached, found, err := w.config.ScanCache.Get(ctx, job.FileHash)
		if err == nil && found {
			// Use cached result.
			if err := job.Start(); err != nil {
				return fmt.Errorf("starting job: %w", err)
			}
			if err := job.Complete(cached); err != nil {
				return fmt.Errorf("completing job: %w", err)
			}
			return w.config.JobStore.Update(ctx, job)
		}
	}

	// Start the job.
	if err := job.Start(); err != nil {
		return fmt.Errorf("starting job: %w", err)
	}
	if err := w.config.JobStore.Update(ctx, job); err != nil {
		return fmt.Errorf("updating job status: %w", err)
	}

	// Scan the file.
	var result *types.ScanResult
	if w.config.Scanner != nil {
		result, err = w.config.Scanner.ScanFile(ctx, filePath)
		if err != nil {
			if failErr := job.Fail(err.Error()); failErr != nil {
				return fmt.Errorf("failing job: %w", failErr)
			}
			return w.config.JobStore.Update(ctx, job)
		}
	} else {
		// No scanner available; fail the job.
		if err := job.Fail("scanner not available"); err != nil {
			return fmt.Errorf("failing job: %w", err)
		}
		return w.config.JobStore.Update(ctx, job)
	}

	// Cache the result.
	if w.config.ScanCache != nil && result != nil {
		if err := w.config.ScanCache.Put(ctx, job.FileHash, result); err != nil {
			// Log but don't fail.
			fmt.Printf("Warning: failed to cache result: %v\n", err)
		}
	}

	// Persist malware detection as signature.
	if w.config.SignatureEngine != nil && result != nil {
		if sig := result.ToSignature(); sig != nil {
			if err := w.config.SignatureEngine.AddSignature(ctx, sig); err != nil {
				// Log but don't fail.
				fmt.Printf("Warning: failed to persist signature: %v\n", err)
			}
		}
	}

	// Complete the job.
	if err := job.Complete(result); err != nil {
		return fmt.Errorf("completing job: %w", err)
	}

	return w.config.JobStore.Update(ctx, job)
}

// QueueLength returns the current number of jobs in the queue.
func (w *Worker) QueueLength() int {
	return len(w.jobQueue)
}
