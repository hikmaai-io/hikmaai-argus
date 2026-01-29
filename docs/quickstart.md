# Quick Start Guide

Get HikmaAI Argus running in under 5 minutes. This guide covers installation, basic usage, and verification.

## Prerequisites

- Go 1.23+ (for building from source)
- Make
- ClamAV (optional, for file scanning)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/hikmaai-io/hikmaai-argus.git
cd hikmaai-argus

# Build the binary
make build

# Verify installation
./bin/hikmaai-argus version
```

### Install Globally

```bash
make install
hikmaai-argus version
```

## Basic Usage

### Hash Lookup (No Dependencies)

The simplest operation: lookup a hash against the signature database.

```bash
# Scan the EICAR test hash
hikmaai-argus scan 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Output (without signatures loaded):
# Hash:   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (sha256)
# Status: unknown
# Lookup:  0.05ms (bloom=false)
```

### Loading Test Signatures

To test EICAR detection, use the feeds command:

```bash
# Initialize with EICAR test signatures
hikmaai-argus feeds update --source eicar

# Now scan again
hikmaai-argus scan 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Output:
# Hash:   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (sha256)
# Status: malware
# Detection: EICAR-Test-File
# Threat: testfile
# Severity: low
# Lookup:  0.15ms (bloom=true)
```

### File Scanning (Requires ClamAV)

For full file analysis, ClamAV must be installed:

```bash
# macOS
brew install clamav

# Ubuntu/Debian
sudo apt-get install clamav

# Initialize ClamAV databases
hikmaai-argus feeds update --source clamav-db

# Scan a file
hikmaai-argus scan --with-file /path/to/suspicious.exe

# Scan a directory recursively
hikmaai-argus scan --with-file /path/to/samples/ --recursive
```

## Demo Results

### Clean File

```bash
$ hikmaai-argus scan --with-file /tmp/clean.txt

============================================================
File: /tmp/clean.txt
============================================================
Status: clean
Engine: clamav
Scan Time: 0.45s
File Hash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### EICAR Test Detection

```bash
$ echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
$ hikmaai-argus scan --with-file /tmp/eicar.txt

============================================================
File: /tmp/eicar.txt
============================================================
Status: infected
Detection: Win.Test.EICAR_HDB-1
Threat: testfile
Severity: low
Engine: clamav
Scan Time: 0.52s
```

### Multiple Hash Lookup

```bash
$ hikmaai-argus scan --batch "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,44d88612fea8a8f36de82e1278abb02f"

Hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
Status: malware | Detection: EICAR-Test-File

Hash: 44d88612fea8a8f36de82e1278abb02f
Status: malware | Detection: EICAR-Test-File
```

## Running as a Service

### Start the Daemon

```bash
# Basic daemon (HTTP API only)
hikmaai-argus daemon --http-addr :8080

# With automatic feed updates
hikmaai-argus daemon --http-addr :8080 --feeds-update --feeds-interval 1h

# Full enterprise mode (Redis integration)
hikmaai-argus daemon \
  --http-addr :8080 \
  --argus-worker \
  --redis-addr localhost:6379 \
  --gcs-bucket hikma-skills
```

### Test the HTTP API

```bash
# Health check
curl http://localhost:8080/api/v1/health

# Hash lookup
curl http://localhost:8080/api/v1/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Upload file for scanning
curl -X POST -F "file=@suspicious.exe" http://localhost:8080/api/v1/files

# Poll job result
curl http://localhost:8080/api/v1/jobs/{job_id}
```

## Configuration

### Create Config File

```bash
mkdir -p ~/.config/hikmaai-argus
cp examples/config.yaml ~/.config/hikmaai-argus/config.yaml
```

### Minimal Configuration

```yaml
# ~/.config/hikmaai-argus/config.yaml

# Data directories
data_dir: data/hikmaaidb
clamdb_dir: data/clamdb

# Logging
log:
  level: info
  format: text

# Feeds (signature updates)
feeds:
  update_interval: 1h
  sources:
    - eicar
    - clamav-db
```

### Enable ClamAV Scanning

```yaml
clamav:
  enabled: true
  mode: clamscan
  binary: clamscan
  timeout: 5m
  max_file_size: 104857600  # 100MB
  workers: 2
  cache_ttl: 24h
```

### Enable Trivy Scanning

```yaml
trivy:
  enabled: true
  mode: local        # or "server" for remote Trivy
  binary: trivy
  timeout: 5m
  default_severities:
    - HIGH
    - CRITICAL
  supported_ecosystems:
    - pip
    - npm
    - gomod
    - cargo
```

## Useful Commands

```bash
# List configured feeds
hikmaai-argus feeds list

# Update all feeds
hikmaai-argus feeds update

# Database statistics
hikmaai-argus db stats

# Get signature details
hikmaai-argus db get <hash>

# Show version
hikmaai-argus version

# Help
hikmaai-argus --help
hikmaai-argus scan --help
hikmaai-argus daemon --help
```

## Output Formats

### JSON (for CI/CD)

```bash
hikmaai-argus scan --json 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

```json
{
  "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "hash_type": "sha256",
  "status": "malware",
  "detection": "EICAR-Test-File",
  "threat": "testfile",
  "severity": "low",
  "lookup_time_ms": 0.15,
  "bloom_hit": true
}
```

### Human-Readable (default)

```
Hash:   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (sha256)
Status: malware
Detection: EICAR-Test-File
Threat: testfile
Severity: low
Lookup:  0.15ms (bloom=true)
```

## Running Tests

```bash
# All unit tests
make test

# With race detector
go test -race ./...

# Integration tests (require ClamAV)
go test -v ./internal/scanner/... -run Integration

# Benchmarks
make test-bench
```

## Troubleshooting

### ClamAV Not Found

```bash
# Check if clamscan is installed
which clamscan

# macOS: Install via Homebrew
brew install clamav

# Ubuntu: Install via apt
sudo apt-get install clamav
```

### ClamAV Database Missing

```bash
# Update ClamAV databases via hikmaai-argus
hikmaai-argus feeds update --source clamav-db

# Or use freshclam directly
sudo freshclam
```

### Permission Errors

```bash
# Ensure data directory is writable
mkdir -p data/hikmaaidb data/clamdb
chmod 755 data/hikmaaidb data/clamdb
```

### Redis Connection Failed

```bash
# Check Redis is running
redis-cli ping

# Start Redis (Docker)
docker run -d -p 6379:6379 redis:latest
```

## Next Steps

1. **Read the documentation:**
   - [Architecture](architecture.md) - System design and components
   - [API Reference](api-reference.md) - HTTP API documentation
   - [Redis Integration](Redis-integration.md) - Enterprise integration guide

2. **Try advanced features:**
   ```bash
   # Trivy vulnerability scanning
   hikmaai-argus trivy scan --packages "requests:2.25.0:pip,lodash:4.17.20:npm"

   # Batch hash scanning from file
   hikmaai-argus scan --file hashes.txt
   ```

3. **Integrate with CI/CD:**
   ```bash
   # Fail build if malware detected
   hikmaai-argus scan --with-file ./artifacts/ --fail-on-infected
   ```
