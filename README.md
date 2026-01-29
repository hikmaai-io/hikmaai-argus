# HikmaArgus

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go 1.23+](https://img.shields.io/badge/go-1.23+-blue.svg)](https://go.dev/dl/)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)]()

A high-performance security scanning service combining **hash-based signature lookups**, **ClamAV malware detection**, and **Trivy vulnerability analysis**. Runs standalone or integrates with enterprise platforms via Redis Streams.

Designed for the [HikmaAI](https://hikma.ai) platform with Redis (Agent Skill Security Service) integration for automated skill scanning workflows.

---

## Highlights

- **Multi-Engine Detection** - Hash lookups (O(1)), ClamAV malware scanning, Trivy vulnerability analysis
- **Standalone Operation** - Single binary, no external dependencies required for basic usage
- **Enterprise Ready** - Redis integration via Redis Streams with horizontal scaling support
- **Privacy-First Trivy** - Only package metadata sent; no source code or file contents

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/quickstart.md) | Get started in 5 minutes |
| [Architecture](docs/architecture.md) | System design and components |
| [API Reference](docs/api-reference.md) | HTTP API and NATS messaging |
---

## Installation

**Prerequisites:** Go 1.23+ and Make

```bash
# Clone and build
git clone https://github.com/hikmaai-io/hikmaai-argus.git
cd hikmaai-argus
make build

# Verify
./bin/hikmaai-argus version
```

<details>
<summary><strong>Optional: ClamAV (for file scanning)</strong></summary>

```bash
# macOS
brew install clamav

# Ubuntu/Debian
sudo apt-get install clamav

# Initialize databases
hikmaai-argus feeds update --source clamav-db
```

</details>

---

## Quick Start

### Hash Lookup (No Dependencies)

```bash
# Load EICAR test signatures
hikmaai-argus feeds update --source eicar

# Scan EICAR hash
hikmaai-argus scan 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Output:
# Hash:   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (sha256)
# Status: malware
# Detection: EICAR-Test-File
# Lookup:  0.15ms (bloom=true)
```

### File Scanning (Requires ClamAV)

```bash
# Scan a file
hikmaai-argus scan --with-file /path/to/suspicious.exe

# Scan directory recursively
hikmaai-argus scan --with-file /path/to/samples/ --recursive

# Output as JSON
hikmaai-argus scan --with-file /path/to/file.exe --json
```

### HTTP API

```bash
# Start daemon
hikmaai-argus daemon --http-addr :8080

# Hash lookup
curl http://localhost:8080/api/v1/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Upload file for scanning
curl -X POST -F "file=@suspicious.exe" http://localhost:8080/api/v1/files

# Poll job result
curl http://localhost:8080/api/v1/jobs/{job_id}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        hikmaai-argus                                │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │    CLI      │  │  HTTP API   │  │    NATS     │  │   Redis   │  │
│  │  (scan)     │  │  (REST)     │  │  (Request)  │  │  (tools)  │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘  │
│         │                │                │               │         │
│         ▼                ▼                ▼               ▼         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Lookup Engine                             │   │
│  │  Bloom Filter (O(1) rejection) → BadgerDB (signature store)  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│         │                                                           │
│         ▼                                                           │
│  ┌──────────────────────┐  ┌──────────────────────┐                │
│  │   ClamAV Scanner     │  │   Trivy Scanner      │                │
│  │   (malware)          │  │   (vulnerabilities)  │                │
│  └──────────────────────┘  └──────────────────────┘                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Security Scanners

| Scanner | Detection Method | Scope | Requirements |
|---------|------------------|-------|--------------|
| **Hash Lookup** | Bloom + BadgerDB | Known malware hashes | None |
| **ClamAV** | Signature matching | File content | ClamAV installed |
| **Trivy** | Vulnerability DB | Package dependencies | Trivy binary or server |

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `scan <hash>` | Fast hash lookup |
| `scan --with-file <path>` | ClamAV file scan |
| `scan --batch "hash1,hash2"` | Multiple hash lookup |
| `daemon` | Run as HTTP/NATS service |
| `feeds update` | Update signature databases |
| `feeds list` | List configured feeds |
| `db stats` | Show database statistics |
| `version` | Show version info |

### Common Options

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |
| `--data-dir` | Custom data directory |
| `--http-addr` | HTTP listen address |
| `--feeds-update` | Enable periodic feed updates |
| `--argus-worker` | Enable Redis integration |

---

## Configuration

```yaml
# ~/.config/hikmaai-argus/config.yaml

# Data directories
data_dir: data/hikmaaidb
clamdb_dir: data/clamdb

# Logging
log:
  level: info
  format: text

# Signature feeds
feeds:
  update_interval: 1h
  sources:
    - eicar
    - clamav-db

# ClamAV scanner (optional)
clamav:
  enabled: false
  mode: clamscan
  timeout: 5m

# Trivy scanner (optional)
trivy:
  enabled: false
  mode: local
  default_severities:
    - HIGH
    - CRITICAL

# Redis integration (optional)
redis:
  enabled: false
  addr: localhost:6379
  prefix: "argus:"

gcs:
  enabled: false
  bucket: hikma-skills
```

See [examples/config.yaml](examples/config.yaml) for all options.

---

## Redis Integration (Enterprise)

For integration with the HikmaAI Redis platform:

```bash
hikmaai-argus daemon \
  --argus-worker \
  --redis-addr redis:6379 \
  --redis-prefix "prod:" \
  --gcs-bucket hikma-skills
```

**Features:**
- Redis Streams for task queue (XREADGROUP consumer groups)
- GCS integration for skill archive downloads
- Multi-tenant isolation via key prefix
- Real-time job state for polling
- Horizontal scaling support

---

## Development

```bash
# Install dependencies
make deps

# Run tests
make test

# Run tests with coverage
make test-cover

# Run linters
make lint

# Build
make build
```

### Running Tests

```bash
# Unit tests (fast)
go test ./... -short

# All tests including integration
go test ./...

# With race detector
go test -race ./...

# Benchmarks
go test -bench=. ./internal/engine/
```

---

## Known Test Hashes

### EICAR Test File

| Algorithm | Hash |
|-----------|------|
| SHA256 | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` |
| SHA1 | `3395856ce81f2b7382dee72602f798b642f14140` |
| MD5 | `44d88612fea8a8f36de82e1278abb02f` |

---

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <a href="https://github.com/hikmaai-io/hikmaai-argus">GitHub</a> •
  <a href="docs/quickstart.md">Quick Start</a> •
  <a href="docs/architecture.md">Architecture</a>
</p>
