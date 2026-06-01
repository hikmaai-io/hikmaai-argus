// ABOUTME: Tests for TrivyJobStore TTL expiry and max-size eviction
// ABOUTME: Ensures the in-memory store does not grow without bound

package api

import (
	"testing"
	"time"
)

func TestTrivyJobStore_TTLExpiry(t *testing.T) {
	t.Parallel()

	s := &TrivyJobStore{
		jobs:    make(map[string]*TrivyJob),
		ttl:     50 * time.Millisecond,
		maxSize: 100,
	}

	s.Set("job-1", &TrivyJob{ID: "job-1", CreatedAt: time.Now()})

	if _, ok := s.Get("job-1"); !ok {
		t.Fatal("expected job-1 present immediately after Set")
	}

	time.Sleep(80 * time.Millisecond)

	if _, ok := s.Get("job-1"); ok {
		t.Error("expected job-1 expired after TTL")
	}
}

func TestTrivyJobStore_MaxSizeEviction(t *testing.T) {
	t.Parallel()

	s := &TrivyJobStore{
		jobs:    make(map[string]*TrivyJob),
		ttl:     time.Hour,
		maxSize: 3,
	}

	base := time.Now()
	// Insert oldest first so eviction order is deterministic.
	s.Set("oldest", &TrivyJob{ID: "oldest", CreatedAt: base})
	s.Set("mid", &TrivyJob{ID: "mid", CreatedAt: base.Add(time.Second)})
	s.Set("new", &TrivyJob{ID: "new", CreatedAt: base.Add(2 * time.Second)})

	// This insert exceeds maxSize and should evict "oldest".
	s.Set("newest", &TrivyJob{ID: "newest", CreatedAt: base.Add(3 * time.Second)})

	if _, ok := s.Get("oldest"); ok {
		t.Error("expected oldest job evicted at capacity")
	}
	if _, ok := s.Get("newest"); !ok {
		t.Error("expected newest job present")
	}
	if len(s.jobs) != 3 {
		t.Errorf("expected store size 3, got %d", len(s.jobs))
	}
}
