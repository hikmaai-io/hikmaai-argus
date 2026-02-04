// ABOUTME: Scanner metrics collection for observability
// ABOUTME: Counters, histograms, and per-scanner statistics

package observability

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsSnapshot contains a point-in-time snapshot of all metrics.
type MetricsSnapshot struct {
	// Total scans attempted.
	ScansTotal int64

	// Successful scans.
	ScansSuccess int64

	// Failed scans.
	ScansFailed int64

	// Files scanned.
	FilesScanned int64

	// Infected files found.
	InfectedFound int64

	// Vulnerabilities found.
	VulnsFound int64

	// Currently active scans.
	ActiveScans int64

	// Queue depth.
	QueueDepth int64

	// Timestamp of snapshot.
	Timestamp time.Time
}

// String returns a human-readable representation.
func (s *MetricsSnapshot) String() string {
	return fmt.Sprintf(
		"scans=%d (success=%d fail=%d) files=%d infected=%d vulns=%d active=%d queue=%d",
		s.ScansTotal, s.ScansSuccess, s.ScansFailed,
		s.FilesScanned, s.InfectedFound, s.VulnsFound,
		s.ActiveScans, s.QueueDepth,
	)
}

// LatencyPercentiles contains latency distribution.
type LatencyPercentiles struct {
	P50 time.Duration
	P75 time.Duration
	P90 time.Duration
	P95 time.Duration
	P99 time.Duration
	Max time.Duration
}

// ScannerStat contains statistics for a specific scanner.
type ScannerStat struct {
	TotalScans     int64
	SuccessCount   int64
	FailureCount   int64
	TotalLatency   time.Duration
	AverageLatency time.Duration
}

// scannerStats holds per-scanner metrics.
type scannerStats struct {
	mu         sync.Mutex
	totalScans int64
	successes  int64
	failures   int64
	latencies  []time.Duration
}

// ScannerMetrics collects metrics for scanner operations.
type ScannerMetrics struct {
	// Atomic counters.
	scansTotal    atomic.Int64
	scansSuccess  atomic.Int64
	scansFailed   atomic.Int64
	filesScanned  atomic.Int64
	infectedFound atomic.Int64
	vulnsFound    atomic.Int64
	activeScans   atomic.Int64
	queueDepth    atomic.Int64

	// Latency histogram (protected by mutex).
	mu        sync.RWMutex
	latencies []time.Duration

	// Per-scanner stats.
	scannerStats map[string]*scannerStats
}

// NewScannerMetrics creates a new metrics collector.
func NewScannerMetrics() *ScannerMetrics {
	return &ScannerMetrics{
		latencies:    make([]time.Duration, 0, 1000),
		scannerStats: make(map[string]*scannerStats),
	}
}

// RecordScan records a scan operation.
func (m *ScannerMetrics) RecordScan(scanner string, duration time.Duration, success bool) {
	m.scansTotal.Add(1)

	if success {
		m.scansSuccess.Add(1)
	} else {
		m.scansFailed.Add(1)
	}

	// Record latency.
	m.mu.Lock()
	m.latencies = append(m.latencies, duration)

	// Limit latency slice size.
	if len(m.latencies) > 10000 {
		m.latencies = m.latencies[len(m.latencies)-5000:]
	}

	// Record per-scanner stats.
	stats, ok := m.scannerStats[scanner]
	if !ok {
		stats = &scannerStats{}
		m.scannerStats[scanner] = stats
	}
	m.mu.Unlock()

	stats.mu.Lock()
	stats.totalScans++
	if success {
		stats.successes++
	} else {
		stats.failures++
	}
	stats.latencies = append(stats.latencies, duration)
	if len(stats.latencies) > 1000 {
		stats.latencies = stats.latencies[len(stats.latencies)-500:]
	}
	stats.mu.Unlock()
}

// RecordFilesScanned records the number of files scanned.
func (m *ScannerMetrics) RecordFilesScanned(count int64) {
	m.filesScanned.Add(count)
}

// RecordInfectedFound records the number of infected files found.
func (m *ScannerMetrics) RecordInfectedFound(count int64) {
	m.infectedFound.Add(count)
}

// RecordVulnsFound records the number of vulnerabilities found.
func (m *ScannerMetrics) RecordVulnsFound(count int64) {
	m.vulnsFound.Add(count)
}

// IncrementActiveScans increments the active scan counter.
func (m *ScannerMetrics) IncrementActiveScans() {
	m.activeScans.Add(1)
}

// DecrementActiveScans decrements the active scan counter.
func (m *ScannerMetrics) DecrementActiveScans() {
	m.activeScans.Add(-1)
}

// SetQueueDepth sets the current queue depth.
func (m *ScannerMetrics) SetQueueDepth(depth int64) {
	m.queueDepth.Store(depth)
}

// Snapshot returns a point-in-time snapshot of all metrics.
func (m *ScannerMetrics) Snapshot() *MetricsSnapshot {
	return &MetricsSnapshot{
		ScansTotal:    m.scansTotal.Load(),
		ScansSuccess:  m.scansSuccess.Load(),
		ScansFailed:   m.scansFailed.Load(),
		FilesScanned:  m.filesScanned.Load(),
		InfectedFound: m.infectedFound.Load(),
		VulnsFound:    m.vulnsFound.Load(),
		ActiveScans:   m.activeScans.Load(),
		QueueDepth:    m.queueDepth.Load(),
		Timestamp:     time.Now(),
	}
}

// LatencyPercentiles returns latency distribution percentiles.
func (m *ScannerMetrics) LatencyPercentiles() LatencyPercentiles {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.latencies) == 0 {
		return LatencyPercentiles{}
	}

	// Make a copy and sort.
	sorted := make([]time.Duration, len(m.latencies))
	copy(sorted, m.latencies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	return LatencyPercentiles{
		P50: percentile(sorted, 50),
		P75: percentile(sorted, 75),
		P90: percentile(sorted, 90),
		P95: percentile(sorted, 95),
		P99: percentile(sorted, 99),
		Max: sorted[len(sorted)-1],
	}
}

// percentile calculates the pth percentile of a sorted slice.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ScannerStats returns per-scanner statistics.
func (m *ScannerMetrics) ScannerStats() map[string]*ScannerStat {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ScannerStat, len(m.scannerStats))
	for name, stats := range m.scannerStats {
		stats.mu.Lock()
		stat := &ScannerStat{
			TotalScans:   stats.totalScans,
			SuccessCount: stats.successes,
			FailureCount: stats.failures,
		}
		if len(stats.latencies) > 0 {
			var total time.Duration
			for _, lat := range stats.latencies {
				total += lat
			}
			stat.TotalLatency = total
			stat.AverageLatency = total / time.Duration(len(stats.latencies))
		}
		stats.mu.Unlock()
		result[name] = stat
	}
	return result
}

// Reset resets all metrics to zero.
func (m *ScannerMetrics) Reset() {
	m.scansTotal.Store(0)
	m.scansSuccess.Store(0)
	m.scansFailed.Store(0)
	m.filesScanned.Store(0)
	m.infectedFound.Store(0)
	m.vulnsFound.Store(0)
	m.activeScans.Store(0)
	m.queueDepth.Store(0)

	m.mu.Lock()
	m.latencies = m.latencies[:0]
	m.scannerStats = make(map[string]*scannerStats)
	m.mu.Unlock()
}

// String returns a summary string.
func (m *ScannerMetrics) String() string {
	snapshot := m.Snapshot()
	percentiles := m.LatencyPercentiles()

	var sb strings.Builder
	sb.WriteString(snapshot.String())
	sb.WriteString(fmt.Sprintf(" p50=%v p99=%v", percentiles.P50, percentiles.P99))
	return sb.String()
}
