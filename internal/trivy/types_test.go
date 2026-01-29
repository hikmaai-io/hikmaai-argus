// ABOUTME: Unit tests for Trivy dependency scanner types
// ABOUTME: Tests package validation, ecosystem validation, and JSON serialization

package trivy

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPackage_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pkg     Package
		wantErr bool
	}{
		{
			name: "valid pip package",
			pkg: Package{
				Name:      "requests",
				Version:   "2.25.0",
				Ecosystem: EcosystemPip,
			},
			wantErr: false,
		},
		{
			name: "valid npm package",
			pkg: Package{
				Name:      "lodash",
				Version:   "4.17.20",
				Ecosystem: EcosystemNpm,
			},
			wantErr: false,
		},
		{
			name: "valid gomod package",
			pkg: Package{
				Name:      "github.com/gin-gonic/gin",
				Version:   "v1.9.0",
				Ecosystem: EcosystemGomod,
			},
			wantErr: false,
		},
		{
			name: "valid cargo package",
			pkg: Package{
				Name:      "serde",
				Version:   "1.0.0",
				Ecosystem: EcosystemCargo,
			},
			wantErr: false,
		},
		{
			name: "valid composer package",
			pkg: Package{
				Name:      "symfony/console",
				Version:   "5.4.0",
				Ecosystem: EcosystemComposer,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			pkg: Package{
				Name:      "",
				Version:   "1.0.0",
				Ecosystem: EcosystemPip,
			},
			wantErr: true,
		},
		{
			name: "empty version",
			pkg: Package{
				Name:      "requests",
				Version:   "",
				Ecosystem: EcosystemPip,
			},
			wantErr: true,
		},
		{
			name: "empty ecosystem",
			pkg: Package{
				Name:      "requests",
				Version:   "1.0.0",
				Ecosystem: "",
			},
			wantErr: true,
		},
		{
			name: "unsupported ecosystem",
			pkg: Package{
				Name:      "some-package",
				Version:   "1.0.0",
				Ecosystem: "unsupported",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.pkg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Package.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPackage_CacheKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pkg  Package
		want string
	}{
		{
			name: "pip package",
			pkg: Package{
				Name:      "requests",
				Version:   "2.25.0",
				Ecosystem: EcosystemPip,
			},
			want: "trivy:pkg:pip:requests:2.25.0",
		},
		{
			name: "npm package with scope",
			pkg: Package{
				Name:      "@angular/core",
				Version:   "15.0.0",
				Ecosystem: EcosystemNpm,
			},
			want: "trivy:pkg:npm:@angular/core:15.0.0",
		},
		{
			name: "gomod package with path",
			pkg: Package{
				Name:      "github.com/gin-gonic/gin",
				Version:   "v1.9.0",
				Ecosystem: EcosystemGomod,
			},
			want: "trivy:pkg:gomod:github.com/gin-gonic/gin:v1.9.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.pkg.CacheKey(); got != tt.want {
				t.Errorf("Package.CacheKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanRequest_Validate(t *testing.T) {
	t.Parallel()

	validPackage := Package{
		Name:      "requests",
		Version:   "2.25.0",
		Ecosystem: EcosystemPip,
	}

	tests := []struct {
		name    string
		req     ScanRequest
		wantErr bool
	}{
		{
			name: "valid request with packages",
			req: ScanRequest{
				Packages:       []Package{validPackage},
				SeverityFilter: []string{SeverityHigh, SeverityCritical},
			},
			wantErr: false,
		},
		{
			name: "valid request without severity filter",
			req: ScanRequest{
				Packages: []Package{validPackage},
			},
			wantErr: false,
		},
		{
			name: "empty packages",
			req: ScanRequest{
				Packages: []Package{},
			},
			wantErr: true,
		},
		{
			name: "nil packages",
			req: ScanRequest{
				Packages: nil,
			},
			wantErr: true,
		},
		{
			name: "invalid package in list",
			req: ScanRequest{
				Packages: []Package{
					{Name: "", Version: "1.0.0", Ecosystem: EcosystemPip},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid severity filter",
			req: ScanRequest{
				Packages:       []Package{validPackage},
				SeverityFilter: []string{"INVALID"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVulnerability_MatchesSeverityFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		vuln     Vulnerability
		filter   []string
		expected bool
	}{
		{
			name:     "critical matches critical filter",
			vuln:     Vulnerability{Severity: SeverityCritical},
			filter:   []string{SeverityCritical},
			expected: true,
		},
		{
			name:     "high matches high and critical filter",
			vuln:     Vulnerability{Severity: SeverityHigh},
			filter:   []string{SeverityHigh, SeverityCritical},
			expected: true,
		},
		{
			name:     "medium does not match high filter",
			vuln:     Vulnerability{Severity: SeverityMedium},
			filter:   []string{SeverityHigh, SeverityCritical},
			expected: false,
		},
		{
			name:     "empty filter matches all",
			vuln:     Vulnerability{Severity: SeverityLow},
			filter:   []string{},
			expected: true,
		},
		{
			name:     "nil filter matches all",
			vuln:     Vulnerability{Severity: SeverityMedium},
			filter:   nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.vuln.MatchesSeverityFilter(tt.filter); got != tt.expected {
				t.Errorf("Vulnerability.MatchesSeverityFilter() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestScanResult_FilterBySeverity(t *testing.T) {
	t.Parallel()

	result := ScanResult{
		Vulnerabilities: []Vulnerability{
			{Package: "pkg1", Severity: SeverityCritical, CVEID: "CVE-2023-0001"},
			{Package: "pkg2", Severity: SeverityHigh, CVEID: "CVE-2023-0002"},
			{Package: "pkg3", Severity: SeverityMedium, CVEID: "CVE-2023-0003"},
			{Package: "pkg4", Severity: SeverityLow, CVEID: "CVE-2023-0004"},
		},
		Summary: ScanSummary{
			TotalVulnerabilities: 4,
			Critical:             1,
			High:                 1,
			Medium:               1,
			Low:                  1,
			PackagesScanned:      4,
		},
	}

	filtered := result.FilterBySeverity([]string{SeverityHigh, SeverityCritical})

	if len(filtered.Vulnerabilities) != 2 {
		t.Errorf("expected 2 vulnerabilities, got %d", len(filtered.Vulnerabilities))
	}

	if filtered.Summary.TotalVulnerabilities != 2 {
		t.Errorf("expected summary total 2, got %d", filtered.Summary.TotalVulnerabilities)
	}

	if filtered.Summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", filtered.Summary.Critical)
	}

	if filtered.Summary.High != 1 {
		t.Errorf("expected 1 high, got %d", filtered.Summary.High)
	}

	if filtered.Summary.Medium != 0 {
		t.Errorf("expected 0 medium, got %d", filtered.Summary.Medium)
	}
}

func TestPackage_JSONSerialization(t *testing.T) {
	t.Parallel()

	pkg := Package{
		Name:      "requests",
		Version:   "2.25.0",
		Ecosystem: EcosystemPip,
		SrcName:   "python-requests",
	}

	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("failed to marshal package: %v", err)
	}

	var decoded Package
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal package: %v", err)
	}

	if decoded.Name != pkg.Name {
		t.Errorf("name mismatch: got %s, want %s", decoded.Name, pkg.Name)
	}
	if decoded.Version != pkg.Version {
		t.Errorf("version mismatch: got %s, want %s", decoded.Version, pkg.Version)
	}
	if decoded.Ecosystem != pkg.Ecosystem {
		t.Errorf("ecosystem mismatch: got %s, want %s", decoded.Ecosystem, pkg.Ecosystem)
	}
	if decoded.SrcName != pkg.SrcName {
		t.Errorf("srcname mismatch: got %s, want %s", decoded.SrcName, pkg.SrcName)
	}
}

func TestVulnerability_JSONSerialization(t *testing.T) {
	t.Parallel()

	vuln := Vulnerability{
		Package:      "requests",
		Version:      "2.25.0",
		Ecosystem:    EcosystemPip,
		CVEID:        "CVE-2023-32681",
		Severity:     SeverityHigh,
		Title:        "Unintended leak of Proxy-Authorization header",
		Description:  "Requests library leaks proxy credentials",
		FixedVersion: "2.31.0",
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-32681"},
	}

	data, err := json.Marshal(vuln)
	if err != nil {
		t.Fatalf("failed to marshal vulnerability: %v", err)
	}

	var decoded Vulnerability
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal vulnerability: %v", err)
	}

	if decoded.CVEID != vuln.CVEID {
		t.Errorf("cve_id mismatch: got %s, want %s", decoded.CVEID, vuln.CVEID)
	}
	if decoded.Severity != vuln.Severity {
		t.Errorf("severity mismatch: got %s, want %s", decoded.Severity, vuln.Severity)
	}
	if len(decoded.References) != len(vuln.References) {
		t.Errorf("references length mismatch: got %d, want %d", len(decoded.References), len(vuln.References))
	}
}

func TestScanResult_JSONSerialization(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	result := ScanResult{
		Summary: ScanSummary{
			TotalVulnerabilities: 2,
			Critical:             1,
			High:                 1,
			PackagesScanned:      3,
		},
		Vulnerabilities: []Vulnerability{
			{Package: "pkg1", CVEID: "CVE-2023-0001", Severity: SeverityCritical},
			{Package: "pkg2", CVEID: "CVE-2023-0002", Severity: SeverityHigh},
		},
		ScannedAt:  now,
		ScanTimeMs: 150.5,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if decoded.Summary.TotalVulnerabilities != result.Summary.TotalVulnerabilities {
		t.Errorf("total mismatch: got %d, want %d",
			decoded.Summary.TotalVulnerabilities, result.Summary.TotalVulnerabilities)
	}
	if len(decoded.Vulnerabilities) != len(result.Vulnerabilities) {
		t.Errorf("vulnerabilities length mismatch: got %d, want %d",
			len(decoded.Vulnerabilities), len(result.Vulnerabilities))
	}
}

func TestIsValidEcosystem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ecosystem string
		valid     bool
	}{
		{EcosystemPip, true},
		{EcosystemNpm, true},
		{EcosystemGomod, true},
		{EcosystemCargo, true},
		{EcosystemComposer, true},
		{EcosystemMaven, true},
		{EcosystemNuget, true},
		{EcosystemRubygems, true},
		{"unknown", false},
		{"", false},
		{"PIP", false}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(tt.ecosystem, func(t *testing.T) {
			t.Parallel()
			if got := IsValidEcosystem(tt.ecosystem); got != tt.valid {
				t.Errorf("IsValidEcosystem(%q) = %v, want %v", tt.ecosystem, got, tt.valid)
			}
		})
	}
}

func TestIsValidSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity string
		valid    bool
	}{
		{SeverityCritical, true},
		{SeverityHigh, true},
		{SeverityMedium, true},
		{SeverityLow, true},
		{SeverityUnknown, true},
		{"invalid", false},
		{"", false},
		{"critical", false}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			t.Parallel()
			if got := IsValidSeverity(tt.severity); got != tt.valid {
				t.Errorf("IsValidSeverity(%q) = %v, want %v", tt.severity, got, tt.valid)
			}
		})
	}
}

func TestScanSummary_Recalculate(t *testing.T) {
	t.Parallel()

	vulns := []Vulnerability{
		{Severity: SeverityCritical},
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: SeverityMedium},
		{Severity: SeverityMedium},
		{Severity: SeverityLow},
	}

	summary := NewScanSummary(vulns, 10)

	if summary.TotalVulnerabilities != 7 {
		t.Errorf("total mismatch: got %d, want 7", summary.TotalVulnerabilities)
	}
	if summary.Critical != 2 {
		t.Errorf("critical mismatch: got %d, want 2", summary.Critical)
	}
	if summary.High != 1 {
		t.Errorf("high mismatch: got %d, want 1", summary.High)
	}
	if summary.Medium != 3 {
		t.Errorf("medium mismatch: got %d, want 3", summary.Medium)
	}
	if summary.Low != 1 {
		t.Errorf("low mismatch: got %d, want 1", summary.Low)
	}
	if summary.PackagesScanned != 10 {
		t.Errorf("packages scanned mismatch: got %d, want 10", summary.PackagesScanned)
	}
}
