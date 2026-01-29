# HikmaAI Argus Architecture

## Overview

HikmaAI Argus is a modular, high-performance security scanning service designed for threat detection across multiple dimensions: hash-based signature lookups, ClamAV malware analysis, and Trivy vulnerability scanning. Built with a stateless architecture, it supports standalone CLI operation, HTTP API, NATS messaging, and Redis integration via Redis Streams.

**Structure**: Organized by component (cmd/, internal/engine/, internal/scanner/, internal/trivy/, internal/argus/)
**Coverage**: Hash lookups (Bloom + BadgerDB), ClamAV malware scanning, Trivy vulnerability analysis
**Integration**: Redis platform via Redis Streams for enterprise skill scanning workflows

## High-Level Architecture

```mermaid
graph TB
    subgraph Interfaces[User Interfaces]
        CLI[CLI Interface<br/>scan, daemon, feeds, db]
        HTTP[HTTP API<br/>REST endpoints]
        NATS[NATS Messaging<br/>Request/Reply]
        Redis[Redis Streams<br/>Redis Integration]
    end

    subgraph Engine[Lookup Engine]
        Bloom[Bloom Filter<br/>Fast rejection O(1)]
        BadgerDB[BadgerDB<br/>Signature storage]
    end

    subgraph Scanners[Security Scanners]
        ClamAV[ClamAV Scanner<br/>Malware detection]
        Trivy[Trivy Scanner<br/>Vulnerability analysis]
    end

    subgraph Storage[Storage Layer]
        JobStore[Job Store<br/>Async job tracking]
        ScanCache[Scan Cache<br/>Result caching]
        StateManager[State Manager<br/>Redis hash storage]
    end

    subgraph External[External Services]
        GCS[Google Cloud Storage<br/>Skill downloads]
        TrivyServer[Trivy Server<br/>Twirp API]
        ClamDB[ClamAV Databases<br/>CVD files]
    end

    CLI --> Engine
    HTTP --> Engine
    HTTP --> Scanners
    NATS --> Engine
    Redis --> Argus

    subgraph Argus[Argus Worker]
        Worker[Worker Orchestrator<br/>Task processing]
        Runner[Scanner Runner<br/>Parallel execution]
    end

    Engine --> Bloom
    Bloom --> BadgerDB

    Worker --> GCS
    Worker --> Runner
    Runner --> ClamAV
    Runner --> Trivy

    Scanners --> JobStore
    Scanners --> ScanCache
    Worker --> StateManager

    ClamAV --> ClamDB
    Trivy --> TrivyServer

    style Bloom fill:#e1f5ff
    style ClamAV fill:#ffe1f5
    style Trivy fill:#fff5e1
    style Worker fill:#f5ffe1
```

## Core Components

### 1. Lookup Engine (`internal/engine/`)

The lookup engine provides fast O(1) hash-based signature detection using a two-tier approach.

**Key Components:**

- **`Engine`**: Main orchestrator for signature lookups
  - Manages Bloom filter and BadgerDB
  - Provides batch operations for signature management
  - Thread-safe with atomic Bloom filter updates

- **`Store`**: BadgerDB-based persistent storage
  - Stores full signature metadata
  - Supports batch writes for feed imports
  - Handles compaction and cleanup

- **`BloomFilter`**: Memory-efficient probabilistic filter
  - 10M signatures at 0.1% false positive rate
  - Atomic pointer swap for hot reloading
  - Quick rejection for unknown hashes

**Lookup Flow:**

```
1. Hash received → Bloom filter check
   ├─→ Bloom miss → Return "unknown" immediately
   └─→ Bloom hit → Continue to BadgerDB

2. BadgerDB lookup
   ├─→ Found → Return signature with metadata
   └─→ Not found → Return "unknown" (false positive)
```

### 2. ClamAV Scanner (`internal/scanner/`)

Full file analysis via ClamAV for malware detection.

**Key Components:**

- **`ClamAVScanner`**: Interface to ClamAV
  - Supports `clamscan` binary or `clamd` daemon modes
  - Configurable database directory for CVD files
  - Timeout and max file size limits

- **`Worker`**: Async job processor
  - Concurrent scan workers (configurable)
  - Job queue with status tracking
  - Result caching to avoid re-scans

**Scan Flow:**

```
1. File upload → Compute SHA256
2. Check scan cache
   ├─→ Cache hit → Return cached result
   └─→ Cache miss → Queue scan job

3. Worker picks up job
   ├─→ Run clamscan/clamd
   ├─→ Parse output (clean/infected/error)
   ├─→ Cache result
   └─→ Update job status
```

### 3. Trivy Scanner (`internal/trivy/`)

Dependency vulnerability scanning via Trivy with dual-mode support.

**Key Components:**

- **`UnifiedScanner`**: Orchestrates local or server mode
  - **Local mode**: Executes `trivy` binary directly
  - **Server mode**: Connects to Trivy server via Twirp

- **`Client`**: Twirp HTTP client for server mode
  - `PutBlob` → Upload package metadata
  - `PutArtifact` → Register scan artifact
  - `Scan` → Execute vulnerability scan

- **`Cache`**: Per-package vulnerability cache
  - BadgerDB-backed with configurable TTL
  - Cache key: `{ecosystem}:{name}:{version}`

**Privacy-First Design:**

Only package metadata is sent to the Trivy server:
- Package names
- Package versions
- Package ecosystem (pip, npm, gomod, etc.)

**Never sent:**
- File contents or source code
- File paths or directory structure
- Environment variables or secrets

### 4. Argus Worker (`internal/argus/`)

Enterprise integration for Redis platform via Redis Streams.

**Key Components:**

- **`Worker`**: Main orchestrator
  - Consumes tasks from Redis Streams (XREADGROUP)
  - Downloads skills from GCS
  - Runs parallel scanner execution
  - Updates job state for Redis polling
  - Publishes completion signals

- **`Runner`**: Scanner execution
  - Parallel Trivy + ClamAV execution
  - Fail-open semantics (partial results on failures)
  - Aggregates results from all scanners

- **`TaskMessage`**: Task protocol
  - Job ID, organization ID, GCS URI
  - Requested scanners (trivy, clamav)
  - Timeout configuration

**Task Flow:**

```
1. Redis publishes task to Redis Stream
   └─→ {job_id, org_id, gcs_uri, scanners}

2. Worker consumes task (XREADGROUP)
   ├─→ Validate organization path
   ├─→ Download skill from GCS
   └─→ Extract archive if needed

3. Run scanners
   ├─→ Trivy: Vulnerability analysis
   └─→ ClamAV: Malware detection
   (parallel execution, fail-open)

4. Update state in Redis
   └─→ {trivy_status, clamav_status, results}

5. Publish completion signal
   └─→ {job_id, status, results}
```

### 5. Redis Integration (`internal/redis/`)

Redis client layer for Redis integration with multi-tenant support.

**Key Components:**

- **`Client`**: Connection management
  - Configurable key prefix for tenant isolation
  - Connection pooling with health checks
  - Graceful shutdown handling

- **`StreamConsumer`**: Redis Streams consumer
  - XREADGROUP for consumer group support
  - Automatic group creation (MKSTREAM)
  - Reliable acknowledgment (XACK)

- **`StateManager`**: Job state storage
  - Hash-based state (`HSET`/`HGET`)
  - JSON serialization for complex objects
  - Configurable TTL for automatic cleanup

**Key Prefix Pattern:**

```
{prefix}job_state:{job_id}      → Job status hash
{prefix}argus_task_queue        → Input task stream
{prefix}argus_completion:{id}   → Completion signal stream
```

> **See Also**: [Redis Integration Guide](redis-integration.md) for detailed configuration, usage examples, and troubleshooting.

### 6. GCS Integration (`internal/gcs/`)

Google Cloud Storage client for skill artifact downloads.

**Key Features:**

- **URI Parsing**: `gs://bucket/path/to/object`
- **Organization Validation**: Prevents cross-tenant access
- **Checksum Verification**: SHA256 integrity checks
- **Cleanup**: Automatic temp file removal

**Security Controls:**

```go
// Organization path validation
func ValidateOrganizationPath(gcsURI, orgID string) bool {
    // Ensures path contains org prefix
    // Prevents directory traversal attacks
}
```

## Data Models

### Signature (`internal/types/`)

```go
type Signature struct {
    Hash          string    // SHA256, SHA1, or MD5
    HashType      HashType  // sha256, sha1, md5
    DetectionName string    // e.g., "EICAR-Test-File"
    ThreatType    string    // malware, trojan, etc.
    Severity      Severity  // critical, high, medium, low
    Source        string    // eicar, clamav, malwarebazaar
    FirstSeen     time.Time
    LastSeen      time.Time
    Metadata      map[string]string
}
```

### ScanResult (`internal/types/`)

```go
type ScanResult struct {
    Status     ScanStatus // clean, infected, error
    FilePath   string
    FileHash   string
    Detection  string     // Detection name if infected
    ThreatType string
    Severity   Severity
    Engine     string     // clamav, trivy
    ScanTime   time.Duration
    Error      string     // Error message if failed
}
```

### TaskMessage (`internal/argus/`)

```go
type TaskMessage struct {
    JobID          string   `json:"job_id"`
    ReportID       string   `json:"report_id"`
    OrganizationID string   `json:"organization_id"`
    ParentTaskID   string   `json:"parent_task_id"`
    GCSURI         string   `json:"gcs_uri"`
    Scanners       []string `json:"scanners"`
    TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
    CreatedAt      time.Time `json:"created_at"`
}
```

## Configuration

### Core Configuration (`internal/config/`)

```go
type Config struct {
    DataDir     string        // HikmaAI signature storage
    ClamDBDir   string        // ClamAV database directory
    NATS        NATSConfig    // NATS messaging
    HTTP        HTTPConfig    // HTTP API
    Log         LogConfig     // Logging
    Tracing     TracingConfig // OpenTelemetry
    Feeds       FeedsConfig   // Signature feeds
    ClamAV      ClamAVConfig  // ClamAV scanner
    Trivy       TrivyConfig   // Trivy scanner
    Redis       RedisConfig   // Redis integration
    GCS         GCSConfig     // Skill storage
    ArgusWorker ArgusWorkerConfig
}
```

### Standalone vs. Enterprise Mode

| Feature | Standalone | Enterprise (Redis) |
|---------|------------|------------------|
| Hash lookups | CLI/HTTP | CLI/HTTP |
| ClamAV scanning | CLI/HTTP | CLI/HTTP/Argus |
| Trivy scanning | CLI/HTTP | CLI/HTTP/Argus |
| Redis integration | Disabled | Enabled |
| GCS integration | Disabled | Enabled |
| Consumer groups | N/A | Horizontal scaling |

## Data Flow

### CLI Hash Lookup

```
1. User runs: hikmaai-argus scan <hash>

2. CLI parses hash → calls engine.Lookup()
   ├─→ Bloom filter check (0.001ms)
   │   └─→ Miss → Return "unknown"
   │
   └─→ Hit → BadgerDB lookup (0.1ms)
       ├─→ Found → Return signature
       └─→ Not found → Return "unknown"

3. Display result with timing
```

### HTTP File Upload

```
1. POST /api/v1/files with file upload

2. Handler processes upload
   ├─→ Compute SHA256
   ├─→ Check scan cache
   │   └─→ Cache hit → Return cached result (200)
   │
   └─→ Cache miss → Create scan job
       └─→ Return job_id (202)

3. Worker processes job
   ├─→ Run ClamAV scan
   ├─→ Update job status
   └─→ Cache result

4. Client polls GET /api/v1/jobs/{id}
   └─→ Return status/result
```

### Redis Skill Scanning

```
1. Redis publishes to Redis Stream
   └─→ {job_id, gcs_uri, scanners: [trivy, clamav]}

2. Argus Worker consumes (XREADGROUP)
   ├─→ ACK message immediately
   ├─→ Initialize job state in Redis
   └─→ Validate organization path

3. Download and extract
   ├─→ Download from GCS
   ├─→ Verify checksum
   └─→ Extract archive

4. Run scanners (parallel)
   ├─→ Trivy: Parse manifests → Query vulnerabilities
   └─→ ClamAV: Scan all files → Detect malware

5. Update state and complete
   ├─→ Store results in Redis hash
   ├─→ Publish completion signal
   └─→ Cleanup temp files
```

## Extensibility Points

### Adding New Feed Sources

1. Implement the `Feed` interface:

```go
type Feed interface {
    Name() string
    Update(ctx context.Context) ([]types.Signature, error)
}
```

2. Register in feed manager:

```go
manager.Register("my-feed", NewMyFeed(config))
```

### Adding New Scanners

1. Implement scanner interface:

```go
type Scanner interface {
    Scan(ctx context.Context, path string) (*types.ScanResult, error)
    Ping(ctx context.Context) error
}
```

2. Add to Argus runner configuration:

```go
runner := argus.NewRunner(argus.RunnerConfig{
    TrivyScanner:  trivyScanner,
    ClamAVScanner: clamScanner,
    MyScanner:     myScanner,  // New scanner
})
```

### Adding New Output Formats

For CLI output, implement the formatter interface:

```go
type Formatter interface {
    Format(result *types.ScanResult) string
}
```

## Performance Characteristics

### Lookup Performance

| Operation | Latency | Notes |
|-----------|---------|-------|
| Bloom filter check | ~0.001ms | In-memory, constant time |
| BadgerDB lookup | ~0.1ms | LSM-tree, O(log n) |
| Full lookup (hit) | ~0.2ms | Bloom + DB |
| Full lookup (miss) | ~0.001ms | Bloom rejection only |

### Scan Performance

| Operation | Typical Latency | Notes |
|-----------|-----------------|-------|
| ClamAV file scan | 1-10s | Depends on file size |
| Trivy vuln scan | 0.5-5s | Depends on package count |
| GCS download | 1-30s | Depends on archive size |

### Scalability

- **Signatures**: 10M+ with 0.1% false positive rate
- **Concurrent scans**: Configurable worker pool (default: 2)
- **Redis throughput**: Consumer groups for horizontal scaling

## Security Considerations

### Input Validation

- Hash format validation (length, hex chars)
- File size limits (default: 100MB)
- Path traversal prevention
- Organization isolation in GCS paths

### Isolation

- Scan operations are read-only
- No code execution from scanned files
- Temp files cleaned after scan
- Configurable timeouts

### Multi-Tenant Security

- Redis key prefix isolation
- GCS organization path validation
- Job state TTL for automatic cleanup

## Testing Architecture

### Test Structure

```
internal/
├── engine/
│   ├── engine_test.go        # Engine unit tests
│   └── integration_test.go   # EICAR detection tests
├── scanner/
│   ├── clamav_test.go        # Scanner unit tests
│   └── integration_test.go   # ClamAV integration tests
├── trivy/
│   ├── scanner_test.go       # Scanner unit tests
│   └── client_test.go        # Twirp client tests
├── argus/
│   ├── worker_test.go        # Worker unit tests
│   ├── runner_test.go        # Runner unit tests
│   └── types_test.go         # Type validation tests
└── redis/
    ├── client_test.go        # Redis client tests
    ├── streams_test.go       # Streams consumer tests
    └── state_test.go         # State manager tests
```

### Test Categories

- **Unit tests**: Mock dependencies, fast execution
- **Integration tests**: Require external services (ClamAV, Redis)
- **Benchmarks**: Performance regression detection

### Running Tests

```bash
# All unit tests (fast)
go test ./... -short

# With integration tests
go test ./...

# Specific package
go test ./internal/engine/...

# With race detector
go test -race ./...

# Benchmarks
go test -bench=. ./internal/engine/
```

## Deployment Modes

### Standalone CLI

```bash
# Direct hash lookup
hikmaai-argus scan <hash>

# File scanning (requires ClamAV)
hikmaai-argus scan --with-file /path/to/file
```

### HTTP API Server

```bash
hikmaai-argus daemon --http-addr :8080
```

### Redis Integration (Enterprise)

```bash
hikmaai-argus daemon \
  --argus-worker \
  --redis-addr redis:6379 \
  --redis-prefix "prod:" \
  --gcs-bucket hikma-skills
```

## Conclusion

HikmaAI Argus provides a flexible, high-performance security scanning platform that scales from CLI usage to enterprise deployments. The modular architecture allows easy extension with new scanners, feeds, and integrations while maintaining consistent security guarantees across all modes of operation.
