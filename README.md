# HikmaAV

A stateless, signature-based antivirus service with fast hash lookups using a two-tier approach: Bloom filter for quick rejection followed by BadgerDB for confirmed lookups.

## Features

- **Fast Hash Lookups**: O(1) rejection via Bloom filter, O(1) lookup via BadgerDB
- **Multiple Hash Types**: Supports SHA256, SHA1, and MD5
- **NATS Messaging**: Request/reply pattern with queue groups for load balancing
- **Observability**: OpenTelemetry tracing (Tempo) and structured logging (Loki)
- **CLI & Daemon Modes**: Direct database access or daemon with NATS messaging
- **Feed Support**: EICAR test signatures, CSV feeds (abuse.ch format)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    hikma-av binary                               │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  daemon cmd  │  │   scan cmd   │  │      db cmd          │  │
│  │  (service)   │  │   (query)    │  │  (debug/inspect)     │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│         │                │                    │                  │
│         ▼                ▼                    ▼                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Lookup Engine                             ││
│  │  Bloom (atomic.Ptr) → BadgerDB (local)                      ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

**No external dependencies required** - HikmaAV works standalone with just the binary and a data directory. NATS, Grafana, Loki, and Tempo are all optional.

### Build

```bash
# Clone the repository
git clone https://github.com/hikmaai-io/hikma-av.git
cd hikma-av

# Build the binary
make build

# Or install directly
make install
```

### Test the Engine

The simplest way to test the engine is using the built-in EICAR test signatures.

```bash
# Build the binary
make build

# Scan the EICAR test hash (should detect as malware)
./bin/hikma-av scan 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Expected output:
# Hash:   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (sha256)
# Status: unknown
# Lookup:  0.123ms (bloom=false)
```

Note: The scan will return "unknown" because no signatures are loaded yet. To test with EICAR detection, you need to load signatures first (see [Loading EICAR Signatures](#loading-eicar-signatures)).

### Loading EICAR Signatures

For a complete test with EICAR detection, use the Go test suite:

```bash
# Run the integration tests (includes EICAR detection)
go test -v ./internal/engine/... -run Integration

# Example output:
# === RUN   TestIntegration_EICARDetection
# --- PASS: TestIntegration_EICARDetection (0.01s)
```

### Programmatic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/hikmaai-io/hikma-av/internal/engine"
    "github.com/hikmaai-io/hikma-av/internal/feeds"
    "github.com/hikmaai-io/hikma-av/internal/types"
)

func main() {
    ctx := context.Background()

    // Create engine with in-memory storage (for testing)
    eng, err := engine.NewEngine(engine.EngineConfig{
        StoreConfig: engine.StoreConfig{
            InMemory: true, // Use Path: "/path/to/data" for persistence
        },
        BloomConfig: engine.BloomConfig{
            ExpectedItems:     10_000_000,
            FalsePositiveRate: 0.001,
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer eng.Close()

    // Load EICAR test signatures
    eicarSigs := feeds.EICARSignatures()
    if err := eng.BatchAddSignatures(ctx, eicarSigs); err != nil {
        log.Fatal(err)
    }

    // Scan the EICAR hash
    hash, _ := types.ParseHash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    result, err := eng.Lookup(ctx, hash)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %s\n", result.Status)
    if result.Signature != nil {
        fmt.Printf("Detection: %s\n", result.Signature.DetectionName)
    }
    // Output:
    // Status: malware
    // Detection: EICAR-Test-File
}
```

## CLI Reference

### Scan Command

```bash
# Scan a single hash
hikma-av scan <sha256|sha1|md5>

# Scan from file (one hash per line)
hikma-av scan --file hashes.txt

# Scan multiple hashes
hikma-av scan --batch "hash1,hash2,hash3"

# Output as JSON
hikma-av scan --json 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### Daemon Command

```bash
# Run in foreground
hikma-av daemon

# With custom data directory
hikma-av daemon --data-dir /var/lib/hikma-av

# With custom NATS URL
hikma-av daemon --nats-url nats://nats.example.com:4222
```

### Database Commands

```bash
# Show database statistics
hikma-av db stats

# Get signature details for a hash
hikma-av db get 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Trigger compaction
hikma-av db compact
```

### Other Commands

```bash
# Show version
hikma-av version

# Show daemon status
hikma-av status

# List configured feeds
hikma-av feeds list
```

## Configuration

Copy the example configuration and customize:

```bash
mkdir -p ~/.config/hikma-av
cp examples/config.yaml ~/.config/hikma-av/config.yaml
```

See [examples/config.yaml](examples/config.yaml) for all options.

## Development

### Prerequisites

- Go 1.23+
- Make
- Docker (for local services)

### Setup

```bash
# Install development tools
make tools

# Download dependencies
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

### Local Development with Docker

Start the observability stack:

```bash
cd examples
docker compose up -d

# Access Grafana at http://localhost:3000
# NATS monitoring at http://localhost:8222
```

Run the daemon with tracing enabled:

```bash
./bin/hikma-av daemon \
  --log-level debug \
  --log-format text
```

### Running Tests

```bash
# All tests
make test

# With race detector
go test -race ./...

# Integration tests only
go test -v ./internal/engine/... -run Integration

# Benchmarks
make test-bench
```

## NATS Integration

HikmaAV uses NATS for request/reply messaging:

**Subject**: `hikma.av.scan`
**Queue Group**: `av-workers` (for load balancing)

### Request Format

```json
{
  "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "request_id": "optional-correlation-id"
}
```

### Response Format

```json
{
  "request_id": "optional-correlation-id",
  "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "hash_type": "sha256",
  "status": "malware",
  "detection": "EICAR-Test-File",
  "threat": "testfile",
  "severity": "low",
  "source": "eicar",
  "lookup_time_ms": 0.123,
  "bloom_hit": true,
  "scanned_at": "2024-01-01T00:00:00Z"
}
```

### Example with nats-cli

```bash
# Install nats-cli
go install github.com/nats-io/natscli/nats@latest

# Send a scan request
echo '{"hash":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}' | \
  nats request hikma.av.scan
```

## Observability (Optional)

The observability stack (Grafana, Loki, Tempo) is **completely optional**. HikmaAV works standalone without any external dependencies except for the data directory.

To disable tracing, set `tracing.enabled: false` in your config or simply omit the tracing configuration:

```yaml
tracing:
  enabled: false
```

Logging always works and outputs to stdout. You can switch between JSON (for Loki) and text formats:

```yaml
log:
  level: info
  format: text  # Use 'text' for human-readable, 'json' for Loki
```

### Logging (Loki)

Logs are emitted in JSON format with automatic trace ID injection:

```json
{
  "time": "2024-01-01T00:00:00Z",
  "level": "INFO",
  "msg": "processed scan request",
  "service": "hikma-av",
  "version": "1.0.0",
  "trace_id": "abc123...",
  "span_id": "def456...",
  "request_id": "req-123",
  "hash": "275a021b...f651fd0f",
  "status": "malware",
  "duration": "1.234ms"
}
```

### Tracing (Tempo)

Traces are exported via OTLP/gRPC to Tempo. Each scan request creates a span with:

- Hash value and type
- Lookup result (status, detection)
- Bloom filter hit/miss
- Lookup duration

### Grafana Dashboard

Access Grafana at `http://localhost:3000` after starting the Docker stack. Datasources for Loki and Tempo are pre-configured with trace-to-log correlation.

## Known Hashes

### EICAR Test File

The EICAR test file is a standard antivirus test file that all AV products should detect:

| Algorithm | Hash |
|-----------|------|
| SHA256 | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` |
| SHA1 | `3395856ce81f2b7382dee72602f798b642f14140` |
| MD5 | `44d88612fea8a8f36de82e1278abb02f` |

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
