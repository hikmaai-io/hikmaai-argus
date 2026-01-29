// ABOUTME: Unit tests for manifest parser and archive extraction
// ABOUTME: Tests parsing of dependency files and archive handling

package trivy

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseRequirementsTxt(t *testing.T) {
	t.Parallel()

	content := `# This is a comment
requests==2.25.0
flask>=2.0.0
django==4.2.0
numpy  # inline comment
pandas==1.5.0
-e git+https://github.com/user/repo.git#egg=mypackage
./local-package
`

	packages, err := ParseRequirementsTxt([]byte(content))
	if err != nil {
		t.Fatalf("ParseRequirementsTxt() error = %v", err)
	}

	// Should parse 5 packages (skip comments, editable installs, local paths)
	if len(packages) != 5 {
		t.Errorf("expected 5 packages, got %d", len(packages))
	}

	// Check specific packages
	found := make(map[string]string)
	for _, p := range packages {
		found[p.Name] = p.Version
	}

	if v, ok := found["requests"]; !ok || v != "2.25.0" {
		t.Errorf("expected requests==2.25.0, got %s", v)
	}
	if v, ok := found["flask"]; !ok || v != "2.0.0" {
		t.Errorf("expected flask>=2.0.0 parsed as 2.0.0, got %s", v)
	}
}

func TestParsePackageJSON(t *testing.T) {
	t.Parallel()

	content := `{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "4.18.2"
  },
  "devDependencies": {
    "jest": "29.0.0"
  }
}`

	packages, err := ParsePackageJSON([]byte(content))
	if err != nil {
		t.Fatalf("ParsePackageJSON() error = %v", err)
	}

	// Should parse all dependencies (including devDependencies)
	if len(packages) != 3 {
		t.Errorf("expected 3 packages, got %d", len(packages))
	}

	found := make(map[string]string)
	for _, p := range packages {
		found[p.Name] = p.Version
		if p.Ecosystem != EcosystemNpm {
			t.Errorf("expected ecosystem npm, got %s", p.Ecosystem)
		}
	}

	if v, ok := found["lodash"]; !ok || v != "4.17.21" {
		t.Errorf("expected lodash 4.17.21, got %s", v)
	}
}

func TestParseGoMod(t *testing.T) {
	t.Parallel()

	content := `module github.com/example/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/spf13/cobra v1.7.0
	golang.org/x/sync v0.3.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
)
`

	packages, err := ParseGoMod([]byte(content))
	if err != nil {
		t.Fatalf("ParseGoMod() error = %v", err)
	}

	if len(packages) < 3 {
		t.Errorf("expected at least 3 packages, got %d", len(packages))
	}

	found := make(map[string]string)
	for _, p := range packages {
		found[p.Name] = p.Version
		if p.Ecosystem != EcosystemGomod {
			t.Errorf("expected ecosystem gomod, got %s", p.Ecosystem)
		}
	}

	if v, ok := found["github.com/gin-gonic/gin"]; !ok || v != "v1.9.1" {
		t.Errorf("expected gin v1.9.1, got %s", v)
	}
}

func TestParseCargoToml(t *testing.T) {
	t.Parallel()

	content := `[package]
name = "my-app"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.28", features = ["full"] }
reqwest = "0.11.18"

[dev-dependencies]
criterion = "0.5"
`

	packages, err := ParseCargoToml([]byte(content))
	if err != nil {
		t.Fatalf("ParseCargoToml() error = %v", err)
	}

	if len(packages) != 4 {
		t.Errorf("expected 4 packages, got %d", len(packages))
	}

	found := make(map[string]string)
	for _, p := range packages {
		found[p.Name] = p.Version
		if p.Ecosystem != EcosystemCargo {
			t.Errorf("expected ecosystem cargo, got %s", p.Ecosystem)
		}
	}

	if v, ok := found["serde"]; !ok || v != "1.0" {
		t.Errorf("expected serde 1.0, got %s", v)
	}
	if v, ok := found["tokio"]; !ok || v != "1.28" {
		t.Errorf("expected tokio 1.28, got %s", v)
	}
}

func TestParseComposerJSON(t *testing.T) {
	t.Parallel()

	content := `{
  "name": "vendor/project",
  "require": {
    "php": "^8.1",
    "symfony/console": "^6.0",
    "guzzlehttp/guzzle": "^7.5"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.0"
  }
}`

	packages, err := ParseComposerJSON([]byte(content))
	if err != nil {
		t.Fatalf("ParseComposerJSON() error = %v", err)
	}

	// Should skip php requirement, parse 3 packages
	if len(packages) != 3 {
		t.Errorf("expected 3 packages (excluding php), got %d", len(packages))
	}

	for _, p := range packages {
		if p.Ecosystem != EcosystemComposer {
			t.Errorf("expected ecosystem composer, got %s", p.Ecosystem)
		}
	}
}

func TestFindManifests(t *testing.T) {
	t.Parallel()

	// Create temp directory with test files
	dir := t.TempDir()

	// Create nested structure
	subdir := filepath.Join(dir, "app")
	os.MkdirAll(subdir, 0o755)
	os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0o755) // Should be skipped

	// Create manifest files
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.25.0"), 0o644)
	os.WriteFile(filepath.Join(subdir, "package.json"), []byte(`{"dependencies":{}}`), 0o644)
	os.WriteFile(filepath.Join(subdir, "go.mod"), []byte("module test\ngo 1.21"), 0o644)
	os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "package.json"), []byte(`{}`), 0o644) // Should be skipped

	manifests, err := FindManifests(dir)
	if err != nil {
		t.Fatalf("FindManifests() error = %v", err)
	}

	// Should find 3 manifests (skip node_modules)
	if len(manifests) != 3 {
		t.Errorf("expected 3 manifests, got %d: %v", len(manifests), manifests)
	}
}

func TestExtractArchive_Zip(t *testing.T) {
	t.Parallel()

	// Create a zip file with a requirements.txt
	zipPath := filepath.Join(t.TempDir(), "test.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}

	w := zip.NewWriter(zipFile)
	f, _ := w.Create("requirements.txt")
	f.Write([]byte("requests==2.25.0\nflask==2.0.0"))
	f, _ = w.Create("src/main.py")
	f.Write([]byte("print('hello')"))
	w.Close()
	zipFile.Close()

	// Extract
	extractDir, err := ExtractArchive(zipPath)
	if err != nil {
		t.Fatalf("ExtractArchive() error = %v", err)
	}
	defer os.RemoveAll(extractDir)

	// Verify extraction
	content, err := os.ReadFile(filepath.Join(extractDir, "requirements.txt"))
	if err != nil {
		t.Fatalf("failed to read extracted file: %v", err)
	}
	if string(content) != "requests==2.25.0\nflask==2.0.0" {
		t.Errorf("unexpected content: %s", string(content))
	}
}

func TestExtractArchive_TarGz(t *testing.T) {
	t.Parallel()

	// Create a tar.gz file
	tarPath := filepath.Join(t.TempDir(), "test.tar.gz")
	tarFile, err := os.Create(tarPath)
	if err != nil {
		t.Fatalf("failed to create tar.gz: %v", err)
	}

	gzw := gzip.NewWriter(tarFile)
	tw := tar.NewWriter(gzw)

	// Add a file
	content := []byte("requests==2.25.0")
	hdr := &tar.Header{
		Name: "requirements.txt",
		Mode: 0o644,
		Size: int64(len(content)),
	}
	tw.WriteHeader(hdr)
	tw.Write(content)
	tw.Close()
	gzw.Close()
	tarFile.Close()

	// Extract
	extractDir, err := ExtractArchive(tarPath)
	if err != nil {
		t.Fatalf("ExtractArchive() error = %v", err)
	}
	defer os.RemoveAll(extractDir)

	// Verify
	data, err := os.ReadFile(filepath.Join(extractDir, "requirements.txt"))
	if err != nil {
		t.Fatalf("failed to read extracted file: %v", err)
	}
	if string(data) != "requests==2.25.0" {
		t.Errorf("unexpected content: %s", string(data))
	}
}

func TestScanPath_Directory(t *testing.T) {
	t.Parallel()

	// Create temp directory with manifest
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.25.0\nflask==2.0.0"), 0o644)

	packages, err := ScanPathForPackages(dir)
	if err != nil {
		t.Fatalf("ScanPathForPackages() error = %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}
}

func TestScanPath_Archive(t *testing.T) {
	t.Parallel()

	// Create a zip with manifest
	zipPath := filepath.Join(t.TempDir(), "app.zip")
	zipFile, _ := os.Create(zipPath)
	w := zip.NewWriter(zipFile)
	f, _ := w.Create("package.json")
	f.Write([]byte(`{"dependencies":{"lodash":"4.17.21","express":"4.18.0"}}`))
	w.Close()
	zipFile.Close()

	packages, err := ScanPathForPackages(zipPath)
	if err != nil {
		t.Fatalf("ScanPathForPackages() error = %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}
}

func TestDetectManifestType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		filename string
		want     string
	}{
		{"requirements.txt", "pip"},
		{"Pipfile.lock", "pip"},
		{"poetry.lock", "pip"},
		{"package.json", "npm"},
		{"package-lock.json", "npm"},
		{"yarn.lock", "npm"},
		{"go.mod", "gomod"},
		{"go.sum", "gomod"},
		{"Cargo.toml", "cargo"},
		{"Cargo.lock", "cargo"},
		{"composer.json", "composer"},
		{"composer.lock", "composer"},
		{"unknown.txt", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			t.Parallel()
			got := DetectManifestType(tt.filename)
			if got != tt.want {
				t.Errorf("DetectManifestType(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}
