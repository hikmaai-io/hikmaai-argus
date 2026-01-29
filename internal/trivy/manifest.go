// ABOUTME: Manifest parser for extracting packages from dependency files
// ABOUTME: Supports archives (zip, tar.gz) and common package manager manifests

package trivy

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Manifest file patterns.
var manifestFiles = map[string]string{
	"requirements.txt":  "pip",
	"Pipfile.lock":      "pip",
	"poetry.lock":       "pip",
	"package.json":      "npm",
	"package-lock.json": "npm",
	"yarn.lock":         "npm",
	"go.mod":            "gomod",
	"go.sum":            "gomod",
	"Cargo.toml":        "cargo",
	"Cargo.lock":        "cargo",
	"composer.json":     "composer",
	"composer.lock":     "composer",
}

// Directories to skip when scanning.
var skipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"target":       true, // Rust build dir
}

// DetectManifestType returns the ecosystem for a manifest filename.
func DetectManifestType(filename string) string {
	base := filepath.Base(filename)
	return manifestFiles[base]
}

// ScanPathForPackages scans a path (directory or archive) for packages.
// If path is an archive, it extracts to a temp directory first.
func ScanPathForPackages(path string) ([]Package, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("accessing path: %w", err)
	}

	var scanDir string
	var cleanup func()

	if info.IsDir() {
		scanDir = path
	} else if isArchive(path) {
		extractDir, err := ExtractArchive(path)
		if err != nil {
			return nil, fmt.Errorf("extracting archive: %w", err)
		}
		scanDir = extractDir
		cleanup = func() { os.RemoveAll(extractDir) }
	} else {
		return nil, errors.New("path must be a directory or archive")
	}

	if cleanup != nil {
		defer cleanup()
	}

	manifests, err := FindManifests(scanDir)
	if err != nil {
		return nil, fmt.Errorf("finding manifests: %w", err)
	}

	var allPackages []Package
	seen := make(map[string]bool)

	for _, manifest := range manifests {
		packages, err := ParseManifest(manifest)
		if err != nil {
			continue // Skip unparseable manifests
		}

		for _, pkg := range packages {
			key := pkg.CacheKey()
			if !seen[key] {
				seen[key] = true
				allPackages = append(allPackages, pkg)
			}
		}
	}

	return allPackages, nil
}

// FindManifests recursively finds manifest files in a directory.
func FindManifests(dir string) ([]string, error) {
	var manifests []string

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if DetectManifestType(d.Name()) != "" {
			manifests = append(manifests, path)
		}

		return nil
	})

	return manifests, err
}

// ParseManifest parses a manifest file and returns packages.
func ParseManifest(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	filename := filepath.Base(path)

	switch filename {
	case "requirements.txt":
		return ParseRequirementsTxt(data)
	case "package.json":
		return ParsePackageJSON(data)
	case "package-lock.json":
		return ParsePackageLockJSON(data)
	case "go.mod":
		return ParseGoMod(data)
	case "Cargo.toml":
		return ParseCargoToml(data)
	case "Cargo.lock":
		return ParseCargoLock(data)
	case "composer.json":
		return ParseComposerJSON(data)
	case "composer.lock":
		return ParseComposerLock(data)
	default:
		return nil, fmt.Errorf("unsupported manifest: %s", filename)
	}
}

// ParseRequirementsTxt parses a Python requirements.txt file.
func ParseRequirementsTxt(data []byte) ([]Package, error) {
	var packages []Package

	// Regex for package==version, package>=version, etc.
	re := regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*([=<>!~]+)\s*([0-9][^\s#]*)`)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments, empty lines, editable installs, local paths
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "-e") || strings.HasPrefix(line, "-r") ||
			strings.HasPrefix(line, ".") || strings.HasPrefix(line, "/") {
			continue
		}

		// Remove inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Try to parse with version specifier
		if matches := re.FindStringSubmatch(line); matches != nil {
			packages = append(packages, Package{
				Name:      strings.ToLower(matches[1]),
				Version:   matches[3],
				Ecosystem: EcosystemPip,
			})
			continue
		}

		// Package without version
		name := strings.Split(line, "[")[0] // Remove extras like [dev]
		name = strings.TrimSpace(name)
		if name != "" && !strings.Contains(name, "/") {
			packages = append(packages, Package{
				Name:      strings.ToLower(name),
				Version:   "latest",
				Ecosystem: EcosystemPip,
			})
		}
	}

	return packages, scanner.Err()
}

// ParsePackageJSON parses a Node.js package.json file.
func ParsePackageJSON(data []byte) ([]Package, error) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	var packages []Package

	for name, version := range pkg.Dependencies {
		packages = append(packages, Package{
			Name:      name,
			Version:   cleanNpmVersion(version),
			Ecosystem: EcosystemNpm,
		})
	}

	for name, version := range pkg.DevDependencies {
		packages = append(packages, Package{
			Name:      name,
			Version:   cleanNpmVersion(version),
			Ecosystem: EcosystemNpm,
		})
	}

	return packages, nil
}

// ParsePackageLockJSON parses a Node.js package-lock.json file.
func ParsePackageLockJSON(data []byte) ([]Package, error) {
	var lockfile struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	var packages []Package
	seen := make(map[string]bool)

	// NPM v7+ format
	for path, info := range lockfile.Packages {
		if path == "" || info.Version == "" {
			continue
		}
		name := strings.TrimPrefix(path, "node_modules/")
		if seen[name] {
			continue
		}
		seen[name] = true
		packages = append(packages, Package{
			Name:      name,
			Version:   info.Version,
			Ecosystem: EcosystemNpm,
		})
	}

	// NPM v6 format
	for name, info := range lockfile.Dependencies {
		if seen[name] || info.Version == "" {
			continue
		}
		seen[name] = true
		packages = append(packages, Package{
			Name:      name,
			Version:   info.Version,
			Ecosystem: EcosystemNpm,
		})
	}

	return packages, nil
}

// ParseGoMod parses a Go go.mod file.
func ParseGoMod(data []byte) ([]Package, error) {
	var packages []Package

	// Regex for require statements
	requireRe := regexp.MustCompile(`^\s*([^\s]+)\s+(v[^\s]+)`)

	inRequire := false
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// Single-line require
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
		} else if !inRequire {
			continue
		}

		// Remove // indirect comments
		if idx := strings.Index(line, "//"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		if matches := requireRe.FindStringSubmatch(line); matches != nil {
			packages = append(packages, Package{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: EcosystemGomod,
			})
		}
	}

	return packages, scanner.Err()
}

// ParseCargoToml parses a Rust Cargo.toml file.
func ParseCargoToml(data []byte) ([]Package, error) {
	var cargo struct {
		Dependencies    map[string]interface{} `toml:"dependencies"`
		DevDependencies map[string]interface{} `toml:"dev-dependencies"`
	}

	if err := toml.Unmarshal(data, &cargo); err != nil {
		return nil, fmt.Errorf("parsing Cargo.toml: %w", err)
	}

	var packages []Package

	extractVersion := func(deps map[string]interface{}) {
		for name, value := range deps {
			var version string
			switch v := value.(type) {
			case string:
				version = v
			case map[string]interface{}:
				if ver, ok := v["version"].(string); ok {
					version = ver
				}
			}
			if version != "" {
				packages = append(packages, Package{
					Name:      name,
					Version:   version,
					Ecosystem: EcosystemCargo,
				})
			}
		}
	}

	extractVersion(cargo.Dependencies)
	extractVersion(cargo.DevDependencies)

	return packages, nil
}

// ParseCargoLock parses a Rust Cargo.lock file.
func ParseCargoLock(data []byte) ([]Package, error) {
	var lock struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"package"`
	}

	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing Cargo.lock: %w", err)
	}

	var packages []Package
	for _, pkg := range lock.Package {
		packages = append(packages, Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: EcosystemCargo,
		})
	}

	return packages, nil
}

// ParseComposerJSON parses a PHP composer.json file.
func ParseComposerJSON(data []byte) ([]Package, error) {
	var composer struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}

	if err := json.Unmarshal(data, &composer); err != nil {
		return nil, fmt.Errorf("parsing composer.json: %w", err)
	}

	var packages []Package

	for name, version := range composer.Require {
		if name == "php" || strings.HasPrefix(name, "ext-") {
			continue // Skip PHP and extensions
		}
		packages = append(packages, Package{
			Name:      name,
			Version:   cleanComposerVersion(version),
			Ecosystem: EcosystemComposer,
		})
	}

	for name, version := range composer.RequireDev {
		packages = append(packages, Package{
			Name:      name,
			Version:   cleanComposerVersion(version),
			Ecosystem: EcosystemComposer,
		})
	}

	return packages, nil
}

// ParseComposerLock parses a PHP composer.lock file.
func ParseComposerLock(data []byte) ([]Package, error) {
	var lock struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}

	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing composer.lock: %w", err)
	}

	var packages []Package

	for _, pkg := range lock.Packages {
		packages = append(packages, Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: EcosystemComposer,
		})
	}

	for _, pkg := range lock.PackagesDev {
		packages = append(packages, Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: EcosystemComposer,
		})
	}

	return packages, nil
}

// ExtractArchive extracts an archive to a temporary directory.
// Supports zip, tar, tar.gz, and tgz formats.
// Returns the path to the extracted directory; caller must clean up.
func ExtractArchive(path string) (string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	name := strings.ToLower(filepath.Base(path))

	extractDir, err := os.MkdirTemp("", "trivy-extract-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	var extractErr error

	switch {
	case ext == ".zip":
		extractErr = extractZip(path, extractDir)
	case ext == ".gz" || strings.HasSuffix(name, ".tar.gz") || ext == ".tgz":
		extractErr = extractTarGz(path, extractDir)
	case ext == ".tar":
		extractErr = extractTar(path, extractDir)
	default:
		os.RemoveAll(extractDir)
		return "", fmt.Errorf("unsupported archive format: %s", ext)
	}

	if extractErr != nil {
		os.RemoveAll(extractDir)
		return "", extractErr
	}

	return extractDir, nil
}

func extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if err := extractZipFile(f, dest); err != nil {
			return err
		}
	}

	return nil
}

func extractZipFile(f *zip.File, dest string) error {
	// Prevent zip slip
	path := filepath.Join(dest, f.Name)
	if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(dest)+string(os.PathSeparator)) {
		return fmt.Errorf("invalid file path: %s", f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(path, 0o755)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	outFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, rc)
	return err
}

func extractTarGz(src, dest string) error {
	file, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzr.Close()

	return extractTarReader(tar.NewReader(gzr), dest)
}

func extractTar(src, dest string) error {
	file, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	return extractTarReader(tar.NewReader(file), dest)
}

func extractTarReader(tr *tar.Reader, dest string) error {
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		// Prevent path traversal
		path := filepath.Join(dest, header.Name)
		if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(dest)+string(os.PathSeparator)) {
			continue // Skip invalid paths
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			outFile, err := os.Create(path)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}

	return nil
}

// isArchive checks if a file is a supported archive format.
func isArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	name := strings.ToLower(filepath.Base(path))

	return ext == ".zip" || ext == ".tar" || ext == ".gz" ||
		ext == ".tgz" || strings.HasSuffix(name, ".tar.gz")
}

// cleanNpmVersion removes version prefixes like ^, ~, >=.
func cleanNpmVersion(version string) string {
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, "<")
	version = strings.TrimPrefix(version, "=")
	return version
}

// cleanComposerVersion removes version prefixes.
func cleanComposerVersion(version string) string {
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, "<")
	return version
}
