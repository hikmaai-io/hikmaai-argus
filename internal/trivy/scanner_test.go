// ABOUTME: Unit tests for Trivy scanner orchestrator
// ABOUTME: Tests the full Twirp workflow with mocked client and cache

package trivy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestScanner_ScanPackages(t *testing.T) {
	t.Parallel()

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/twirp/trivy.cache.v1.Cache/PutBlob":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "/twirp/trivy.cache.v1.Cache/PutArtifact":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "/twirp/trivy.scanner.v1.Scanner/Scan":
			resp := TwirpScanResponse{
				Results: []TwirpResult{
					{
						Target: "dependency-scan",
						Type:   "pip",
						Vulnerabilities: []TwirpVulnerability{
							{
								VulnerabilityID:  "CVE-2023-32681",
								PkgName:          "requests",
								InstalledVersion: "2.25.0",
								FixedVersion:     "2.31.0",
								Severity:         "HIGH",
								Title:            "Proxy-Auth header leak",
							},
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cache, _ := NewCache(CacheConfig{InMemory: true, TTL: 1 * time.Hour})
	defer cache.Close()

	scanner := NewScanner(ScannerConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
		Cache:     cache,
	})

	packages := []Package{
		{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip},
	}

	result, err := scanner.ScanPackages(context.Background(), packages, nil)
	if err != nil {
		t.Fatalf("ScanPackages() error = %v", err)
	}

	if result.Summary.TotalVulnerabilities != 1 {
		t.Errorf("expected 1 vulnerability, got %d", result.Summary.TotalVulnerabilities)
	}

	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability in list, got %d", len(result.Vulnerabilities))
	}

	vuln := result.Vulnerabilities[0]
	if vuln.CVEID != "CVE-2023-32681" {
		t.Errorf("expected CVE-2023-32681, got %s", vuln.CVEID)
	}
	if vuln.Package != "requests" {
		t.Errorf("expected package 'requests', got %s", vuln.Package)
	}
}

func TestScanner_ScanPackages_WithSeverityFilter(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/twirp/trivy.cache.v1.Cache/PutBlob",
			"/twirp/trivy.cache.v1.Cache/PutArtifact":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "/twirp/trivy.scanner.v1.Scanner/Scan":
			resp := TwirpScanResponse{
				Results: []TwirpResult{
					{
						Target: "dependency-scan",
						Vulnerabilities: []TwirpVulnerability{
							{VulnerabilityID: "CVE-1", PkgName: "pkg1", Severity: "CRITICAL"},
							{VulnerabilityID: "CVE-2", PkgName: "pkg2", Severity: "HIGH"},
							{VulnerabilityID: "CVE-3", PkgName: "pkg3", Severity: "MEDIUM"},
							{VulnerabilityID: "CVE-4", PkgName: "pkg4", Severity: "LOW"},
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cache, _ := NewCache(CacheConfig{InMemory: true, TTL: 1 * time.Hour})
	defer cache.Close()

	scanner := NewScanner(ScannerConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
		Cache:     cache,
	})

	packages := []Package{
		{Name: "pkg1", Version: "1.0.0", Ecosystem: EcosystemPip},
	}

	// Filter to only HIGH and CRITICAL
	result, err := scanner.ScanPackages(context.Background(), packages, []string{SeverityHigh, SeverityCritical})
	if err != nil {
		t.Fatalf("ScanPackages() error = %v", err)
	}

	if result.Summary.TotalVulnerabilities != 2 {
		t.Errorf("expected 2 vulnerabilities (filtered), got %d", result.Summary.TotalVulnerabilities)
	}

	for _, vuln := range result.Vulnerabilities {
		if vuln.Severity != SeverityHigh && vuln.Severity != SeverityCritical {
			t.Errorf("unexpected severity %s in filtered results", vuln.Severity)
		}
	}
}

func TestScanner_ScanPackages_UsesCache(t *testing.T) {
	t.Parallel()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/twirp/trivy.cache.v1.Cache/PutBlob",
			"/twirp/trivy.cache.v1.Cache/PutArtifact":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "/twirp/trivy.scanner.v1.Scanner/Scan":
			callCount++
			resp := TwirpScanResponse{
				Results: []TwirpResult{
					{
						Target: "dependency-scan",
						Vulnerabilities: []TwirpVulnerability{
							{VulnerabilityID: "CVE-1", PkgName: "requests", InstalledVersion: "2.25.0", Severity: "HIGH"},
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cache, _ := NewCache(CacheConfig{InMemory: true, TTL: 1 * time.Hour})
	defer cache.Close()

	scanner := NewScanner(ScannerConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
		Cache:     cache,
	})

	packages := []Package{
		{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip},
	}

	// First call - should hit server
	_, err := scanner.ScanPackages(context.Background(), packages, nil)
	if err != nil {
		t.Fatalf("first ScanPackages() error = %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 server call, got %d", callCount)
	}

	// Second call - should use cache
	result, err := scanner.ScanPackages(context.Background(), packages, nil)
	if err != nil {
		t.Fatalf("second ScanPackages() error = %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected still 1 server call (cached), got %d", callCount)
	}
	if result.Summary.TotalVulnerabilities != 1 {
		t.Errorf("expected 1 vulnerability from cache, got %d", result.Summary.TotalVulnerabilities)
	}
}

func TestScanner_ScanPackages_PartialCache(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/twirp/trivy.cache.v1.Cache/PutBlob",
			"/twirp/trivy.cache.v1.Cache/PutArtifact":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "/twirp/trivy.scanner.v1.Scanner/Scan":
			resp := TwirpScanResponse{
				Results: []TwirpResult{
					{
						Target: "dependency-scan",
						Vulnerabilities: []TwirpVulnerability{
							{VulnerabilityID: "CVE-2", PkgName: "lodash", InstalledVersion: "4.17.20", Severity: "CRITICAL"},
						},
					},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cache, _ := NewCache(CacheConfig{InMemory: true, TTL: 1 * time.Hour})
	defer cache.Close()

	// Pre-populate cache with one package
	pkg1 := Package{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip}
	cache.Set(context.Background(), pkg1, []Vulnerability{
		{Package: "requests", CVEID: "CVE-1", Severity: SeverityHigh},
	})

	scanner := NewScanner(ScannerConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
		Cache:     cache,
	})

	packages := []Package{
		pkg1, // cached
		{Name: "lodash", Version: "4.17.20", Ecosystem: EcosystemNpm}, // not cached
	}

	result, err := scanner.ScanPackages(context.Background(), packages, nil)
	if err != nil {
		t.Fatalf("ScanPackages() error = %v", err)
	}

	// Should have 2 vulnerabilities (1 from cache, 1 from server)
	if result.Summary.TotalVulnerabilities != 2 {
		t.Errorf("expected 2 vulnerabilities, got %d", result.Summary.TotalVulnerabilities)
	}
}

func TestScanner_ScanPackages_NoVulnerabilities(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/twirp/trivy.cache.v1.Cache/PutBlob",
			"/twirp/trivy.cache.v1.Cache/PutArtifact":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "/twirp/trivy.scanner.v1.Scanner/Scan":
			resp := TwirpScanResponse{
				Results: []TwirpResult{
					{Target: "dependency-scan", Vulnerabilities: nil},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cache, _ := NewCache(CacheConfig{InMemory: true, TTL: 1 * time.Hour})
	defer cache.Close()

	scanner := NewScanner(ScannerConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
		Cache:     cache,
	})

	packages := []Package{
		{Name: "safe-package", Version: "1.0.0", Ecosystem: EcosystemPip},
	}

	result, err := scanner.ScanPackages(context.Background(), packages, nil)
	if err != nil {
		t.Fatalf("ScanPackages() error = %v", err)
	}

	if result.Summary.TotalVulnerabilities != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", result.Summary.TotalVulnerabilities)
	}

	if result.Summary.PackagesScanned != 1 {
		t.Errorf("expected 1 package scanned, got %d", result.Summary.PackagesScanned)
	}
}

func TestScanner_ScanPackages_ServerError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/twirp/trivy.cache.v1.Cache/PutBlob":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code":"internal","msg":"database error"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cache, _ := NewCache(CacheConfig{InMemory: true, TTL: 1 * time.Hour})
	defer cache.Close()

	scanner := NewScanner(ScannerConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
		Cache:     cache,
	})

	packages := []Package{
		{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip},
	}

	_, err := scanner.ScanPackages(context.Background(), packages, nil)
	if err == nil {
		t.Error("expected error from server failure, got nil")
	}
}

func TestScanner_ScanPackages_EmptyPackages(t *testing.T) {
	t.Parallel()

	scanner := NewScanner(ScannerConfig{
		ServerURL: "http://unused",
		Timeout:   5 * time.Second,
	})

	_, err := scanner.ScanPackages(context.Background(), []Package{}, nil)
	if err == nil {
		t.Error("expected error for empty packages, got nil")
	}
}

func TestScanner_ScanPackages_AllCached(t *testing.T) {
	t.Parallel()

	// Server should not be called if all packages are cached
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		serverCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cache, _ := NewCache(CacheConfig{InMemory: true, TTL: 1 * time.Hour})
	defer cache.Close()

	// Pre-populate cache
	ctx := context.Background()
	pkg1 := Package{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip}
	pkg2 := Package{Name: "lodash", Version: "4.17.20", Ecosystem: EcosystemNpm}
	cache.Set(ctx, pkg1, []Vulnerability{{CVEID: "CVE-1", Severity: SeverityHigh}})
	cache.Set(ctx, pkg2, []Vulnerability{}) // clean package

	scanner := NewScanner(ScannerConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
		Cache:     cache,
	})

	packages := []Package{pkg1, pkg2}
	result, err := scanner.ScanPackages(ctx, packages, nil)
	if err != nil {
		t.Fatalf("ScanPackages() error = %v", err)
	}

	if serverCalled {
		t.Error("server should not be called when all packages are cached")
	}

	if result.Summary.TotalVulnerabilities != 1 {
		t.Errorf("expected 1 vulnerability, got %d", result.Summary.TotalVulnerabilities)
	}

	if result.Summary.PackagesScanned != 2 {
		t.Errorf("expected 2 packages scanned, got %d", result.Summary.PackagesScanned)
	}
}

func TestGenerateBlobID(t *testing.T) {
	t.Parallel()

	packages := []Package{
		{Name: "requests", Version: "2.25.0", Ecosystem: EcosystemPip},
		{Name: "lodash", Version: "4.17.20", Ecosystem: EcosystemNpm},
	}

	id1 := generateBlobID(packages)
	id2 := generateBlobID(packages)

	if id1 != id2 {
		t.Error("same packages should produce same blob ID")
	}

	// Different packages should produce different ID
	packages2 := []Package{
		{Name: "requests", Version: "2.26.0", Ecosystem: EcosystemPip},
	}
	id3 := generateBlobID(packages2)

	if id1 == id3 {
		t.Error("different packages should produce different blob ID")
	}

	// Verify format
	if len(id1) < 10 || id1[:7] != "sha256:" {
		t.Errorf("blob ID should start with sha256:, got %s", id1)
	}
}
