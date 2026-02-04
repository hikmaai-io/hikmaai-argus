// ABOUTME: Tests for scanner metrics collection system
// ABOUTME: Validates counters, histograms, and metrics exposure

package observability

import (
	"sync"
	"testing"
	"time"
)

func TestScannerMetrics_NewScannerMetrics(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	if m == nil {
		t.Fatal("NewScannerMetrics() returned nil")
	}
}

func TestScannerMetrics_RecordScan_Success(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	m.RecordScan("clamav", 100*time.Millisecond, true)

	snapshot := m.Snapshot()

	if snapshot.ScansTotal != 1 {
		t.Errorf("ScansTotal = %d, want 1", snapshot.ScansTotal)
	}
	if snapshot.ScansSuccess != 1 {
		t.Errorf("ScansSuccess = %d, want 1", snapshot.ScansSuccess)
	}
	if snapshot.ScansFailed != 0 {
		t.Errorf("ScansFailed = %d, want 0", snapshot.ScansFailed)
	}
}

func TestScannerMetrics_RecordScan_Failure(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	m.RecordScan("clamav", 50*time.Millisecond, false)

	snapshot := m.Snapshot()

	if snapshot.ScansTotal != 1 {
		t.Errorf("ScansTotal = %d, want 1", snapshot.ScansTotal)
	}
	if snapshot.ScansFailed != 1 {
		t.Errorf("ScansFailed = %d, want 1", snapshot.ScansFailed)
	}
}

func TestScannerMetrics_RecordFilesScanned(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	m.RecordFilesScanned(100)
	m.RecordFilesScanned(50)

	snapshot := m.Snapshot()

	if snapshot.FilesScanned != 150 {
		t.Errorf("FilesScanned = %d, want 150", snapshot.FilesScanned)
	}
}

func TestScannerMetrics_RecordInfectedFound(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	m.RecordInfectedFound(5)
	m.RecordInfectedFound(3)

	snapshot := m.Snapshot()

	if snapshot.InfectedFound != 8 {
		t.Errorf("InfectedFound = %d, want 8", snapshot.InfectedFound)
	}
}

func TestScannerMetrics_RecordVulnsFound(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	m.RecordVulnsFound(10)
	m.RecordVulnsFound(7)

	snapshot := m.Snapshot()

	if snapshot.VulnsFound != 17 {
		t.Errorf("VulnsFound = %d, want 17", snapshot.VulnsFound)
	}
}

func TestScannerMetrics_ActiveScans(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	m.IncrementActiveScans()
	m.IncrementActiveScans()

	snapshot := m.Snapshot()
	if snapshot.ActiveScans != 2 {
		t.Errorf("ActiveScans = %d, want 2", snapshot.ActiveScans)
	}

	m.DecrementActiveScans()

	snapshot = m.Snapshot()
	if snapshot.ActiveScans != 1 {
		t.Errorf("ActiveScans after decrement = %d, want 1", snapshot.ActiveScans)
	}
}

func TestScannerMetrics_QueueDepth(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	m.SetQueueDepth(10)

	snapshot := m.Snapshot()
	if snapshot.QueueDepth != 10 {
		t.Errorf("QueueDepth = %d, want 10", snapshot.QueueDepth)
	}

	m.SetQueueDepth(5)

	snapshot = m.Snapshot()
	if snapshot.QueueDepth != 5 {
		t.Errorf("QueueDepth after update = %d, want 5", snapshot.QueueDepth)
	}
}

func TestScannerMetrics_LatencyPercentiles(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	// Record various latencies.
	latencies := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		100 * time.Millisecond,
		500 * time.Millisecond,
	}

	for _, lat := range latencies {
		m.RecordScan("clamav", lat, true)
	}

	percentiles := m.LatencyPercentiles()

	// P50 should be around 30ms.
	if percentiles.P50 < 20*time.Millisecond || percentiles.P50 > 100*time.Millisecond {
		t.Errorf("P50 = %v, expected ~30ms", percentiles.P50)
	}

	// P99 should be around 500ms.
	if percentiles.P99 < 100*time.Millisecond {
		t.Errorf("P99 = %v, expected >= 100ms", percentiles.P99)
	}
}

func TestScannerMetrics_ScannerStats(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	m.RecordScan("clamav", 100*time.Millisecond, true)
	m.RecordScan("clamav", 200*time.Millisecond, false)
	m.RecordScan("trivy", 50*time.Millisecond, true)

	stats := m.ScannerStats()

	if len(stats) != 2 {
		t.Errorf("ScannerStats() returned %d scanners, want 2", len(stats))
	}

	clamav := stats["clamav"]
	if clamav == nil {
		t.Fatal("clamav stats not found")
	}
	if clamav.TotalScans != 2 {
		t.Errorf("clamav.TotalScans = %d, want 2", clamav.TotalScans)
	}
	if clamav.SuccessCount != 1 {
		t.Errorf("clamav.SuccessCount = %d, want 1", clamav.SuccessCount)
	}
	if clamav.FailureCount != 1 {
		t.Errorf("clamav.FailureCount = %d, want 1", clamav.FailureCount)
	}
}

func TestScannerMetrics_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordScan("clamav", 10*time.Millisecond, true)
			m.RecordFilesScanned(1)
			m.IncrementActiveScans()
			m.DecrementActiveScans()
		}()
	}
	wg.Wait()

	snapshot := m.Snapshot()

	if snapshot.ScansTotal != 100 {
		t.Errorf("ScansTotal = %d, want 100", snapshot.ScansTotal)
	}
	if snapshot.FilesScanned != 100 {
		t.Errorf("FilesScanned = %d, want 100", snapshot.FilesScanned)
	}
	if snapshot.ActiveScans != 0 {
		t.Errorf("ActiveScans = %d, want 0", snapshot.ActiveScans)
	}
}

func TestScannerMetrics_Reset(t *testing.T) {
	t.Parallel()

	m := NewScannerMetrics()

	m.RecordScan("clamav", 100*time.Millisecond, true)
	m.RecordFilesScanned(50)
	m.RecordInfectedFound(5)

	m.Reset()

	snapshot := m.Snapshot()

	if snapshot.ScansTotal != 0 {
		t.Errorf("ScansTotal after reset = %d, want 0", snapshot.ScansTotal)
	}
	if snapshot.FilesScanned != 0 {
		t.Errorf("FilesScanned after reset = %d, want 0", snapshot.FilesScanned)
	}
	if snapshot.InfectedFound != 0 {
		t.Errorf("InfectedFound after reset = %d, want 0", snapshot.InfectedFound)
	}
}

func TestMetricsSnapshot_String(t *testing.T) {
	t.Parallel()

	snapshot := &MetricsSnapshot{
		ScansTotal:    100,
		ScansSuccess:  90,
		ScansFailed:   10,
		FilesScanned:  1000,
		InfectedFound: 5,
	}

	str := snapshot.String()
	if str == "" {
		t.Error("String() should not be empty")
	}
}
