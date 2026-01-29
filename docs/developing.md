# Development Guide

This guide covers setting up a development environment, running tests, and contributing to HikmaArgus.

## Prerequisites

- Go 1.23+
- Make
- Docker (optional, for services)
- ClamAV (optional, for file scanning tests)
- Redis (optional, for AS3 integration tests)

## Setup

### Clone and Build

```bash
git clone https://github.com/hikmaai-io/hikmaai-argus.git
cd hikmaai-argus

# Install development tools
make tools

# Download dependencies
make deps

# Build
make build

# Verify
./bin/hikmaai-argus version
```

### Install Development Tools

```bash
# golangci-lint for linting
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# mockgen for generating mocks
go install go.uber.org/mock/mockgen@latest

# gofumpt for formatting
go install mvdan.cc/gofumpt@latest
```

## Project Structure

```
hikmaai-argus/
├── cmd/
│   └── hikmaai-argus/     # CLI entrypoint
│       ├── main.go        # Main entry
│       ├── root.go        # Root command
│       ├── daemon.go      # Daemon command
│       ├── scan.go        # Scan command
│       ├── feeds.go       # Feeds command
│       └── db.go          # Database command
│
├── internal/
│   ├── api/               # HTTP handlers
│   ├── argus/             # AS3 worker orchestrator
│   ├── config/            # Configuration
│   ├── engine/            # Lookup engine (Bloom + BadgerDB)
│   ├── feeds/             # Signature feed sources
│   ├── gcs/               # GCS client
│   ├── observability/     # Logging and tracing
│   ├── queue/             # NATS messaging
│   ├── redis/             # Redis client
│   ├── scanner/           # ClamAV scanner
│   ├── trivy/             # Trivy scanner
│   └── types/             # Shared types
│
├── docs/                  # Documentation
├── examples/              # Configuration examples
└── Makefile               # Build automation
```

## Running Tests

### All Tests

```bash
# Unit tests only (fast, no external deps)
make test-short
# or
go test ./... -short

# All tests including integration
make test
# or
go test ./...

# With verbose output
go test -v ./...

# With race detector
go test -race ./...
```

### Specific Packages

```bash
# Engine tests
go test -v ./internal/engine/...

# Scanner tests
go test -v ./internal/scanner/...

# API tests
go test -v ./internal/api/...

# Argus worker tests
go test -v ./internal/argus/...
```

### Integration Tests

Integration tests require external services:

```bash
# ClamAV integration (requires clamscan)
go test -v ./internal/scanner/... -run Integration

# Redis integration (requires Redis)
REDIS_INTEGRATION_TEST=true go test -v ./internal/redis/...

# GCS integration (requires GCS access)
GCS_INTEGRATION_TEST=true go test -v ./internal/gcs/...
```

### Benchmarks

```bash
# Engine benchmarks
go test -bench=. ./internal/engine/

# All benchmarks
make test-bench
```

### Coverage

```bash
# Generate coverage report
make test-cover

# View coverage in browser
go tool cover -html=coverage.out
```

## Linting

```bash
# Run all linters
make lint

# Or directly
golangci-lint run

# Fix auto-fixable issues
golangci-lint run --fix
```

### Linter Configuration

See `.golangci.yaml` for configuration. Key linters enabled:

- `errcheck` - Check error handling
- `govet` - Go vet checks
- `staticcheck` - Static analysis
- `gosec` - Security checks
- `gofmt` - Formatting
- `misspell` - Spelling

## Local Development

### Start Services (Docker)

```bash
cd examples

# Start all services (Redis, NATS, etc.)
docker compose up -d

# View logs
docker compose logs -f

# Stop services
docker compose down
```

### Run Daemon

```bash
# Basic daemon
./bin/hikmaai-argus daemon --http-addr :8080

# With feed updates
./bin/hikmaai-argus daemon --http-addr :8080 --feeds-update

# With AS3 integration
./bin/hikmaai-argus daemon \
  --http-addr :8080 \
  --argus-worker \
  --redis-addr localhost:6379
```

### Test HTTP API

```bash
# Health check
curl http://localhost:8080/api/v1/health

# Hash lookup
curl http://localhost:8080/api/v1/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Upload file
curl -X POST -F "file=@testfile.txt" http://localhost:8080/api/v1/files
```

## Code Style

### File Headers

All new files should start with ABOUTME comments:

```go
// ABOUTME: Brief description of file purpose
// ABOUTME: Key context or dependencies

package mypackage
```

### Error Handling

Always wrap errors with context:

```go
// Good
if err != nil {
    return fmt.Errorf("processing job %s: %w", jobID, err)
}

// Bad
if err != nil {
    return err
}
```

### Testing

Use table-driven tests:

```go
func TestParseHash(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name    string
        input   string
        want    Hash
        wantErr bool
    }{
        {
            name:  "valid sha256",
            input: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            want:  Hash{Type: SHA256, Value: "275a..."},
        },
        {
            name:    "invalid length",
            input:   "abc",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()

            got, err := ParseHash(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseHash() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !tt.wantErr && got != tt.want {
                t.Errorf("ParseHash() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Interfaces

Keep interfaces small and define them at the consumer site:

```go
// Good: Small interface defined where used
type hashLookup interface {
    Lookup(ctx context.Context, hash types.Hash) (*types.LookupResult, error)
}

// Bad: Large interface defined at provider
type EngineInterface interface {
    Lookup(...)
    BatchAdd(...)
    GetStats(...)
    Close()
    // ... many more
}
```

## Adding New Features

### Adding a New Scanner

1. Create package under `internal/`:
   ```
   internal/myscanner/
   ├── scanner.go      # Main implementation
   ├── scanner_test.go # Tests
   └── types.go        # Types if needed
   ```

2. Implement the scanner interface:
   ```go
   type Scanner interface {
       Scan(ctx context.Context, path string) (*types.ScanResult, error)
       Ping(ctx context.Context) error
   }
   ```

3. Add configuration to `internal/config/config.go`

4. Wire into daemon in `cmd/hikmaai-argus/daemon.go`

5. Add to Argus runner if needed for AS3 integration

### Adding a New Feed Source

1. Implement the Feed interface in `internal/feeds/`:
   ```go
   type Feed interface {
       Name() string
       Update(ctx context.Context) ([]types.Signature, error)
   }
   ```

2. Register in the feed manager

3. Add to default configuration

### Adding New API Endpoints

1. Add handler in `internal/api/handlers.go`
2. Register route in `RegisterRoutes()`
3. Add tests in `internal/api/handlers_test.go`
4. Update `docs/api-reference.md`

## Git Workflow

### Commit Messages

Use conventional commits:

```
feat: add Trivy vulnerability scanning
fix: handle empty hash in lookup
docs: update API reference
test: add integration tests for ClamAV
refactor: extract hash validation
chore: update dependencies
```

### Branch Strategy

- `main` - Stable release branch
- `feature/*` - New features
- `fix/*` - Bug fixes

### Pull Request Process

1. Create feature branch
2. Make changes with tests
3. Run `make lint test`
4. Create PR with description
5. Address review feedback
6. Squash and merge

## Debugging

### Enable Debug Logging

```bash
./bin/hikmaai-argus daemon --log-level debug
```

### Profile CPU/Memory

```bash
# CPU profile
go test -cpuprofile cpu.prof -bench=. ./internal/engine/
go tool pprof cpu.prof

# Memory profile
go test -memprofile mem.prof -bench=. ./internal/engine/
go tool pprof mem.prof
```

### Trace Execution

```bash
# Generate trace
go test -trace trace.out ./internal/engine/...
go tool trace trace.out
```

## Release Process

1. Update version in `cmd/hikmaai-argus/main.go`
2. Update CHANGELOG
3. Create git tag: `git tag v1.x.x`
4. Push tag: `git push origin v1.x.x`
5. Build releases: `make release`

## Getting Help

- Check existing issues on GitHub
- Review the documentation in `docs/`
- Ask in team channels
