// ABOUTME: JobStore persists scan jobs in BadgerDB
// ABOUTME: Provides CRUD operations and status-based queries for async scan jobs

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/hikmaai-io/hikma-av/internal/types"
)

const (
	jobPrefix     = "job:"
	jobHashPrefix = "job-hash:"
)

// JobStore provides persistence for scan jobs.
type JobStore struct {
	db *badger.DB
}

// NewJobStore creates a new job store using the given configuration.
func NewJobStore(cfg StoreConfig) (*JobStore, error) {
	opts := badger.DefaultOptions(cfg.Path)

	if cfg.InMemory {
		opts = opts.WithInMemory(true)
	}

	if cfg.SyncWrites {
		opts = opts.WithSyncWrites(true)
	}

	if cfg.Logger != nil {
		opts = opts.WithLogger(cfg.Logger)
	} else {
		opts = opts.WithLogger(nil)
	}

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("opening badger db: %w", err)
	}

	return &JobStore{db: db}, nil
}

// Close closes the database.
func (s *JobStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Create stores a new job.
func (s *JobStore) Create(ctx context.Context, job *types.Job) error {
	if job == nil {
		return fmt.Errorf("job is nil")
	}

	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshaling job: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		// Store job by ID.
		jobKey := jobPrefix + job.ID
		if err := txn.Set([]byte(jobKey), data); err != nil {
			return fmt.Errorf("setting job key: %w", err)
		}

		// Store index by file hash for lookup.
		if job.FileHash != "" {
			hashKey := jobHashPrefix + job.FileHash
			if err := txn.Set([]byte(hashKey), []byte(job.ID)); err != nil {
				return fmt.Errorf("setting hash index: %w", err)
			}
		}

		return nil
	})
}

// Get retrieves a job by ID.
// Returns nil if the job doesn't exist.
func (s *JobStore) Get(ctx context.Context, id string) (*types.Job, error) {
	var job *types.Job

	err := s.db.View(func(txn *badger.Txn) error {
		key := jobPrefix + id
		item, err := txn.Get([]byte(key))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return fmt.Errorf("getting job: %w", err)
		}

		return item.Value(func(val []byte) error {
			job = &types.Job{}
			if err := json.Unmarshal(val, job); err != nil {
				return fmt.Errorf("unmarshaling job: %w", err)
			}
			return nil
		})
	})

	return job, err
}

// Update updates an existing job.
func (s *JobStore) Update(ctx context.Context, job *types.Job) error {
	if job == nil {
		return fmt.Errorf("job is nil")
	}

	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshaling job: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		key := jobPrefix + job.ID
		return txn.Set([]byte(key), data)
	})
}

// Delete removes a job by ID.
func (s *JobStore) Delete(ctx context.Context, id string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		// Get job first to delete hash index.
		key := jobPrefix + id
		item, err := txn.Get([]byte(key))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return fmt.Errorf("getting job for deletion: %w", err)
		}

		// Delete hash index.
		err = item.Value(func(val []byte) error {
			var job types.Job
			if err := json.Unmarshal(val, &job); err != nil {
				return nil // Ignore unmarshal errors during delete.
			}
			if job.FileHash != "" {
				hashKey := jobHashPrefix + job.FileHash
				txn.Delete([]byte(hashKey))
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Delete job.
		return txn.Delete([]byte(key))
	})
}

// List returns jobs, optionally filtered by status.
// If no status is provided, all jobs are returned.
func (s *JobStore) List(ctx context.Context, statuses ...types.JobStatus) ([]*types.Job, error) {
	var jobs []*types.Job

	statusSet := make(map[types.JobStatus]bool)
	for _, status := range statuses {
		statusSet[status] = true
	}

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(jobPrefix)
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()

			err := item.Value(func(val []byte) error {
				var job types.Job
				if err := json.Unmarshal(val, &job); err != nil {
					return nil // Skip malformed entries.
				}

				// Filter by status if specified.
				if len(statusSet) > 0 && !statusSet[job.Status] {
					return nil
				}

				jobs = append(jobs, &job)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return jobs, err
}

// GetByFileHash finds a job by file hash.
// Returns nil if no job exists for that hash.
func (s *JobStore) GetByFileHash(ctx context.Context, fileHash string) (*types.Job, error) {
	var jobID string

	err := s.db.View(func(txn *badger.Txn) error {
		key := jobHashPrefix + fileHash
		item, err := txn.Get([]byte(key))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return fmt.Errorf("getting hash index: %w", err)
		}

		return item.Value(func(val []byte) error {
			jobID = string(val)
			return nil
		})
	})

	if err != nil || jobID == "" {
		return nil, err
	}

	return s.Get(ctx, jobID)
}

// Cleanup removes completed/failed jobs older than the given age.
// Returns the number of jobs deleted.
func (s *JobStore) Cleanup(ctx context.Context, maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	var toDelete []string

	// Find old jobs.
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(jobPrefix)
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()

			err := item.Value(func(val []byte) error {
				var job types.Job
				if err := json.Unmarshal(val, &job); err != nil {
					return nil
				}

				// Only delete terminal jobs that are old enough.
				if job.Status.IsTerminal() && job.CompletedAt != nil {
					if job.CompletedAt.Before(cutoff) {
						toDelete = append(toDelete, job.ID)
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return 0, err
	}

	// Delete old jobs.
	for _, id := range toDelete {
		if err := s.Delete(ctx, id); err != nil {
			return len(toDelete), err
		}
	}

	return len(toDelete), nil
}

// Count returns the number of jobs in the store.
func (s *JobStore) Count(ctx context.Context) (int64, error) {
	var count int64

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = []byte(jobPrefix)
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		return nil
	})

	return count, err
}
