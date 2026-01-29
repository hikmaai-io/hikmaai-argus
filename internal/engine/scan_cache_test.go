// ABOUTME: Tests for ScanCache that caches scan results by file hash
// ABOUTME: Validates get/put operations and TTL-based expiration

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/hikmaai-io/hikmaai-argus/internal/types"
)

func TestScanCache_Put_Get(t *testing.T) {
	t.Parallel()

	cache := setupTestScanCache(t, 24*time.Hour)

	result := types.NewCleanScanResult("/path/to/file.txt", "abc123hash", 1024)

	// Put result.
	err := cache.Put(context.Background(), "abc123hash", result)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Get result.
	cached, found, err := cache.Get(context.Background(), "abc123hash")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !found {
		t.Fatal("Get() found = false, want true")
	}

	if cached.FileHash != result.FileHash {
		t.Errorf("FileHash = %q, want %q", cached.FileHash, result.FileHash)
	}
	if cached.Status != result.Status {
		t.Errorf("Status = %v, want %v", cached.Status, result.Status)
	}
}

func TestScanCache_Get_NotFound(t *testing.T) {
	t.Parallel()

	cache := setupTestScanCache(t, 24*time.Hour)

	_, found, err := cache.Get(context.Background(), "nonexistent-hash")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if found {
		t.Error("Get() found = true, want false for nonexistent hash")
	}
}

func TestScanCache_Put_Infected(t *testing.T) {
	t.Parallel()

	cache := setupTestScanCache(t, 24*time.Hour)

	result := types.NewInfectedScanResult("/path/to/malware.exe", "def456hash", 2048, "Win.Trojan.Agent")

	err := cache.Put(context.Background(), "def456hash", result)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	cached, found, err := cache.Get(context.Background(), "def456hash")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !found {
		t.Fatal("Get() found = false, want true")
	}

	if cached.Status != types.ScanStatusInfected {
		t.Errorf("Status = %v, want %v", cached.Status, types.ScanStatusInfected)
	}
	if cached.Detection != "Win.Trojan.Agent" {
		t.Errorf("Detection = %q, want %q", cached.Detection, "Win.Trojan.Agent")
	}
}

func TestScanCache_TTL_Expiration(t *testing.T) {
	// Not parallel due to time-sensitive nature.

	// Use short TTL for testing (1 second is the minimum that works reliably).
	cache := setupTestScanCache(t, 1*time.Second)

	result := types.NewCleanScanResult("/path/to/file.txt", "abc123hash", 1024)

	err := cache.Put(context.Background(), "abc123hash", result)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Should be found immediately.
	_, found, err := cache.Get(context.Background(), "abc123hash")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !found {
		t.Error("Get() immediately after Put() should find result")
	}

	// Wait for TTL to expire.
	time.Sleep(1500 * time.Millisecond)

	// Should be expired now.
	_, found, _ = cache.Get(context.Background(), "abc123hash")
	if found {
		t.Error("Get() after TTL should not find result")
	}
}

func TestScanCache_Delete(t *testing.T) {
	t.Parallel()

	cache := setupTestScanCache(t, 24*time.Hour)

	result := types.NewCleanScanResult("/path/to/file.txt", "abc123hash", 1024)
	cache.Put(context.Background(), "abc123hash", result)

	// Delete.
	err := cache.Delete(context.Background(), "abc123hash")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Should not be found.
	_, found, _ := cache.Get(context.Background(), "abc123hash")
	if found {
		t.Error("Get() after Delete() should not find result")
	}
}

func TestScanCache_Delete_NotFound(t *testing.T) {
	t.Parallel()

	cache := setupTestScanCache(t, 24*time.Hour)

	// Delete nonexistent entry should not error.
	err := cache.Delete(context.Background(), "nonexistent-hash")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestScanCache_Clear(t *testing.T) {
	t.Parallel()

	cache := setupTestScanCache(t, 24*time.Hour)

	// Add multiple entries.
	cache.Put(context.Background(), "hash1", types.NewCleanScanResult("/path1", "hash1", 1024))
	cache.Put(context.Background(), "hash2", types.NewCleanScanResult("/path2", "hash2", 2048))
	cache.Put(context.Background(), "hash3", types.NewCleanScanResult("/path3", "hash3", 4096))

	// Clear all.
	err := cache.Clear(context.Background())
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	// All should be gone.
	for _, hash := range []string{"hash1", "hash2", "hash3"} {
		_, found, _ := cache.Get(context.Background(), hash)
		if found {
			t.Errorf("Get(%q) after Clear() should not find result", hash)
		}
	}
}

func TestScanCache_Count(t *testing.T) {
	t.Parallel()

	cache := setupTestScanCache(t, 24*time.Hour)

	// Initially empty.
	count, err := cache.Count(context.Background())
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 0 {
		t.Errorf("Count() = %d, want 0", count)
	}

	// Add entries.
	cache.Put(context.Background(), "hash1", types.NewCleanScanResult("/path1", "hash1", 1024))
	cache.Put(context.Background(), "hash2", types.NewCleanScanResult("/path2", "hash2", 2048))

	count, err = cache.Count(context.Background())
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 2 {
		t.Errorf("Count() = %d, want 2", count)
	}
}

func TestScanCache_Update(t *testing.T) {
	t.Parallel()

	cache := setupTestScanCache(t, 24*time.Hour)

	// Put initial result.
	result1 := types.NewCleanScanResult("/path/to/file.txt", "abc123hash", 1024)
	cache.Put(context.Background(), "abc123hash", result1)

	// Update with new result.
	result2 := types.NewInfectedScanResult("/path/to/file.txt", "abc123hash", 1024, "NewDetection")
	cache.Put(context.Background(), "abc123hash", result2)

	// Get should return updated result.
	cached, found, _ := cache.Get(context.Background(), "abc123hash")
	if !found {
		t.Fatal("Get() found = false, want true")
	}
	if cached.Status != types.ScanStatusInfected {
		t.Errorf("Status = %v, want %v", cached.Status, types.ScanStatusInfected)
	}
	if cached.Detection != "NewDetection" {
		t.Errorf("Detection = %q, want %q", cached.Detection, "NewDetection")
	}
}

// setupTestScanCache creates an in-memory scan cache for testing.
func setupTestScanCache(t *testing.T, ttl time.Duration) *ScanCache {
	t.Helper()

	cache, err := NewScanCache(StoreConfig{InMemory: true}, ttl)
	if err != nil {
		t.Fatalf("NewScanCache() error = %v", err)
	}

	t.Cleanup(func() {
		cache.Close()
	})

	return cache
}
