// ABOUTME: Unit tests for per-package vulnerability cache
// ABOUTME: Tests Get, Set, Delete operations and TTL expiration

package trivy

import (
	"context"
	"testing"
	"time"
)

func TestCache_GetSet(t *testing.T) {
	t.Parallel()

	cache, err := NewCache(CacheConfig{
		InMemory: true,
		TTL:      1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()
	pkg := Package{
		Name:      "requests",
		Version:   "2.25.0",
		Ecosystem: EcosystemPip,
	}

	vulns := []Vulnerability{
		{
			Package:  "requests",
			Version:  "2.25.0",
			CVEID:    "CVE-2023-32681",
			Severity: SeverityHigh,
		},
	}

	// Initially should not exist
	_, found, err := cache.Get(ctx, pkg)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if found {
		t.Error("expected package not found initially")
	}

	// Set the entry
	if err := cache.Set(ctx, pkg, vulns); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Now should exist
	got, found, err := cache.Get(ctx, pkg)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !found {
		t.Error("expected package found after set")
	}
	if len(got) != 1 {
		t.Errorf("got %d vulnerabilities, want 1", len(got))
	}
	if got[0].CVEID != "CVE-2023-32681" {
		t.Errorf("got CVE %s, want CVE-2023-32681", got[0].CVEID)
	}
}

func TestCache_Delete(t *testing.T) {
	t.Parallel()

	cache, err := NewCache(CacheConfig{
		InMemory: true,
		TTL:      1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()
	pkg := Package{
		Name:      "lodash",
		Version:   "4.17.20",
		Ecosystem: EcosystemNpm,
	}

	vulns := []Vulnerability{
		{Package: "lodash", CVEID: "CVE-2021-23337", Severity: SeverityCritical},
	}

	// Set and verify
	if err := cache.Set(ctx, pkg, vulns); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	_, found, _ := cache.Get(ctx, pkg)
	if !found {
		t.Fatal("expected package found after set")
	}

	// Delete
	if err := cache.Delete(ctx, pkg); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Should not exist after delete
	_, found, _ = cache.Get(ctx, pkg)
	if found {
		t.Error("expected package not found after delete")
	}
}

func TestCache_EmptyVulnerabilities(t *testing.T) {
	t.Parallel()

	cache, err := NewCache(CacheConfig{
		InMemory: true,
		TTL:      1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()
	pkg := Package{
		Name:      "safe-package",
		Version:   "1.0.0",
		Ecosystem: EcosystemPip,
	}

	// Set empty vulnerabilities (clean package)
	if err := cache.Set(ctx, pkg, []Vulnerability{}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, found, err := cache.Get(ctx, pkg)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !found {
		t.Error("expected package found after set")
	}
	if len(got) != 0 {
		t.Errorf("expected 0 vulnerabilities for clean package, got %d", len(got))
	}
}

func TestCache_MultiplePackages(t *testing.T) {
	t.Parallel()

	cache, err := NewCache(CacheConfig{
		InMemory: true,
		TTL:      1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()

	packages := []Package{
		{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip},
		{Name: "lodash", Version: "4.17.20", Ecosystem: EcosystemNpm},
		{Name: "github.com/gin-gonic/gin", Version: "v1.9.0", Ecosystem: EcosystemGomod},
	}

	for i, pkg := range packages {
		vulns := []Vulnerability{
			{Package: pkg.Name, CVEID: "CVE-2023-" + string(rune('A'+i)), Severity: SeverityHigh},
		}
		if err := cache.Set(ctx, pkg, vulns); err != nil {
			t.Fatalf("Set(%s) error = %v", pkg.Name, err)
		}
	}

	// Verify all packages are stored correctly
	for i, pkg := range packages {
		got, found, err := cache.Get(ctx, pkg)
		if err != nil {
			t.Fatalf("Get(%s) error = %v", pkg.Name, err)
		}
		if !found {
			t.Errorf("package %s not found", pkg.Name)
			continue
		}
		expectedCVE := "CVE-2023-" + string(rune('A'+i))
		if got[0].CVEID != expectedCVE {
			t.Errorf("package %s: got CVE %s, want %s", pkg.Name, got[0].CVEID, expectedCVE)
		}
	}
}

func TestCache_SameNameDifferentVersions(t *testing.T) {
	t.Parallel()

	cache, err := NewCache(CacheConfig{
		InMemory: true,
		TTL:      1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()

	pkg1 := Package{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip}
	pkg2 := Package{Name: "requests", Version: "2.31.0", Ecosystem: EcosystemPip}

	// 2.25.0 has vulnerabilities
	if err := cache.Set(ctx, pkg1, []Vulnerability{
		{CVEID: "CVE-2023-32681", Severity: SeverityHigh},
	}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// 2.31.0 is clean
	if err := cache.Set(ctx, pkg2, []Vulnerability{}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Verify they are stored separately
	vulns1, found1, _ := cache.Get(ctx, pkg1)
	vulns2, found2, _ := cache.Get(ctx, pkg2)

	if !found1 || !found2 {
		t.Fatal("both versions should be found")
	}

	if len(vulns1) != 1 {
		t.Errorf("2.25.0 should have 1 vulnerability, got %d", len(vulns1))
	}
	if len(vulns2) != 0 {
		t.Errorf("2.31.0 should have 0 vulnerabilities, got %d", len(vulns2))
	}
}

func TestCache_GetMultiple(t *testing.T) {
	t.Parallel()

	cache, err := NewCache(CacheConfig{
		InMemory: true,
		TTL:      1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()

	packages := []Package{
		{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip},
		{Name: "lodash", Version: "4.17.20", Ecosystem: EcosystemNpm},
		{Name: "unknown", Version: "1.0.0", Ecosystem: EcosystemPip},
	}

	// Set first two packages
	cache.Set(ctx, packages[0], []Vulnerability{{CVEID: "CVE-1"}})
	cache.Set(ctx, packages[1], []Vulnerability{{CVEID: "CVE-2"}})
	// packages[2] is not set

	cached, uncached := cache.GetMultiple(ctx, packages)

	if len(cached) != 2 {
		t.Errorf("expected 2 cached packages, got %d", len(cached))
	}
	if len(uncached) != 1 {
		t.Errorf("expected 1 uncached package, got %d", len(uncached))
	}
	if uncached[0].Name != "unknown" {
		t.Errorf("expected uncached package 'unknown', got %s", uncached[0].Name)
	}
}

func TestCache_Cleanup(t *testing.T) {
	t.Parallel()

	// Use a longer TTL to ensure data survives long enough to be read
	cache, err := NewCache(CacheConfig{
		InMemory: true,
		TTL:      5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()
	pkg := Package{
		Name:      "expiring",
		Version:   "1.0.0",
		Ecosystem: EcosystemPip,
	}

	if err := cache.Set(ctx, pkg, []Vulnerability{{CVEID: "CVE-1"}}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Should exist immediately
	vulns, found, err := cache.Get(ctx, pkg)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !found {
		t.Error("expected package found immediately after set")
	}
	if len(vulns) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulns))
	}

	// Cleanup should not delete non-expired entries
	deleted, err := cache.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted entries (not expired), got %d", deleted)
	}

	// Entry should still exist
	_, found, err = cache.Get(ctx, pkg)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !found {
		t.Error("expected package still found after cleanup of non-expired data")
	}
}

func TestCacheKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pkg  Package
		want string
	}{
		{
			pkg:  Package{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip},
			want: "trivy:pkg:pip:requests:2.25.0",
		},
		{
			pkg:  Package{Name: "@angular/core", Version: "15.0.0", Ecosystem: EcosystemNpm},
			want: "trivy:pkg:npm:@angular/core:15.0.0",
		},
		{
			pkg:  Package{Name: "github.com/gin-gonic/gin", Version: "v1.9.0", Ecosystem: EcosystemGomod},
			want: "trivy:pkg:gomod:github.com/gin-gonic/gin:v1.9.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.pkg.Name, func(t *testing.T) {
			t.Parallel()
			if got := tt.pkg.CacheKey(); got != tt.want {
				t.Errorf("CacheKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
