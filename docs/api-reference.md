# API Reference

HikmaArgus provides multiple interfaces for security scanning: HTTP REST API, NATS messaging, and Redis Streams for AS3 integration. This document covers all available endpoints and message formats.

## HTTP REST API

Base URL: `http://localhost:8080/api/v1`

### Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/files/{hash}` | Hash lookup |
| `POST` | `/files` | Upload file for scanning |
| `GET` | `/jobs/{id}` | Get scan job status |
| `POST` | `/dependencies/scan` | Submit dependency scan |
| `GET` | `/dependencies/jobs/{id}` | Get dependency scan result |

---

### Health Check

**Endpoint:** `GET /api/v1/health`

Returns service health status.

**Response:**

```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime": "2h15m30s"
}
```

---

### Hash Lookup

**Endpoint:** `GET /api/v1/files/{hash}`

Fast O(1) hash lookup against the signature database.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | string | SHA256, SHA1, or MD5 hash |

**Response (Malware Found):**

```json
{
  "status": "malware",
  "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "hash_type": "sha256",
  "signature": {
    "detection_name": "EICAR-Test-File",
    "threat_type": "testfile",
    "severity": "low",
    "source": "eicar",
    "first_seen": "2024-01-01T00:00:00Z"
  },
  "lookup_time_ms": 0.15,
  "bloom_hit": true
}
```

**Response (Unknown):**

```json
{
  "status": "unknown",
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "hash_type": "sha256",
  "lookup_time_ms": 0.05,
  "bloom_hit": false
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Invalid hash format |
| 500 | Internal error |

---

### File Upload (Async Scan)

**Endpoint:** `POST /api/v1/files`

Upload a file for ClamAV scanning. Returns immediately with a job ID for polling.

**Request:**

```bash
curl -X POST -F "file=@suspicious.exe" http://localhost:8080/api/v1/files
```

**Response (Scan Queued - 202):**

```json
{
  "job_id": "job_abc123def456",
  "status": "pending",
  "file_hash": "sha256:a1b2c3d4e5f6...",
  "file_name": "suspicious.exe",
  "file_size": 123456,
  "message": "scan queued"
}
```

**Response (Cache Hit - 200):**

If the file was previously scanned and cached:

```json
{
  "cached": true,
  "file_hash": "sha256:a1b2c3d4e5f6...",
  "result": {
    "status": "clean",
    "engine": "clamav",
    "scan_time_ms": 567.89
  }
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Cached result returned |
| 202 | Scan job queued |
| 400 | Invalid request (missing file, too large) |
| 413 | File too large (> max_file_size) |
| 500 | Internal error |

---

### Get Scan Job

**Endpoint:** `GET /api/v1/jobs/{id}`

Poll for scan job status and results.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Job ID from file upload |

**Response (Pending):**

```json
{
  "id": "job_abc123def456",
  "status": "pending",
  "file_hash": "sha256:a1b2c3d4e5f6...",
  "file_name": "suspicious.exe",
  "file_size": 123456,
  "created_at": "2024-01-01T12:00:00Z"
}
```

**Response (Running):**

```json
{
  "id": "job_abc123def456",
  "status": "running",
  "file_hash": "sha256:a1b2c3d4e5f6...",
  "file_name": "suspicious.exe",
  "file_size": 123456,
  "created_at": "2024-01-01T12:00:00Z",
  "started_at": "2024-01-01T12:00:01Z"
}
```

**Response (Completed - Clean):**

```json
{
  "id": "job_abc123def456",
  "status": "completed",
  "file_hash": "sha256:a1b2c3d4e5f6...",
  "file_name": "clean.txt",
  "file_size": 123456,
  "result": {
    "status": "clean",
    "engine": "clamav",
    "scan_time_ms": 450.5
  },
  "created_at": "2024-01-01T12:00:00Z",
  "started_at": "2024-01-01T12:00:01Z",
  "completed_at": "2024-01-01T12:00:05Z"
}
```

**Response (Completed - Infected):**

```json
{
  "id": "job_abc123def456",
  "status": "completed",
  "file_hash": "sha256:a1b2c3d4e5f6...",
  "file_name": "malware.exe",
  "file_size": 123456,
  "result": {
    "status": "infected",
    "detection": "Win.Trojan.Agent-12345",
    "threat_type": "trojan",
    "severity": "critical",
    "engine": "clamav",
    "scan_time_ms": 1234.56
  },
  "created_at": "2024-01-01T12:00:00Z",
  "started_at": "2024-01-01T12:00:01Z",
  "completed_at": "2024-01-01T12:00:10Z"
}
```

**Response (Failed):**

```json
{
  "id": "job_abc123def456",
  "status": "failed",
  "error": "scan timeout exceeded",
  "created_at": "2024-01-01T12:00:00Z",
  "started_at": "2024-01-01T12:00:01Z",
  "completed_at": "2024-01-01T12:05:01Z"
}
```

**Status Codes:**

| Code | Description |
|------|-------------|
| 200 | Success |
| 404 | Job not found |
| 500 | Internal error |

---

### Dependency Vulnerability Scan

**Endpoint:** `POST /api/v1/dependencies/scan`

Submit a list of packages for vulnerability scanning via Trivy.

**Request:**

```json
{
  "packages": [
    {"name": "requests", "version": "2.25.0", "ecosystem": "pip"},
    {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
    {"name": "github.com/gin-gonic/gin", "version": "v1.9.0", "ecosystem": "gomod"}
  ],
  "severity_filter": ["HIGH", "CRITICAL"]
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `packages` | array | Yes | List of packages to scan |
| `packages[].name` | string | Yes | Package name |
| `packages[].version` | string | Yes | Package version |
| `packages[].ecosystem` | string | Yes | Ecosystem: pip, npm, gomod, cargo, composer |
| `severity_filter` | array | No | Filter by severity levels |

**Response (202 Accepted):**

```json
{
  "job_id": "trivy_job_xyz789",
  "status": "pending",
  "message": "vulnerability scan queued"
}
```

---

### Get Dependency Scan Result

**Endpoint:** `GET /api/v1/dependencies/jobs/{id}`

Poll for dependency scan results.

**Response (Completed):**

```json
{
  "job_id": "trivy_job_xyz789",
  "status": "completed",
  "summary": {
    "total_vulnerabilities": 5,
    "critical": 1,
    "high": 3,
    "medium": 1,
    "low": 0,
    "packages_scanned": 3
  },
  "vulnerabilities": [
    {
      "package": "requests",
      "version": "2.25.0",
      "ecosystem": "pip",
      "cve_id": "CVE-2023-32681",
      "severity": "HIGH",
      "title": "Unintended leak of Proxy-Authorization header",
      "description": "Requests can leak Proxy-Authorization headers...",
      "fixed_version": "2.31.0",
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
      ]
    }
  ],
  "scanned_at": "2024-01-01T12:00:05Z",
  "scan_time_ms": 1500.5
}
```

---

## NATS Messaging

HikmaArgus supports NATS request/reply pattern for hash lookups.

### Configuration

```yaml
nats:
  url: nats://localhost:4222
  subject: hikma.av.scan
  queue: av-workers
```

### Subject

`hikma.av.scan` (configurable)

### Queue Group

`av-workers` - Enables load balancing across multiple instances.

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
  "lookup_time_ms": 0.15,
  "bloom_hit": true,
  "scanned_at": "2024-01-01T12:00:00Z"
}
```

### Example with nats-cli

```bash
# Send request
echo '{"hash":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}' | \
  nats request hikma.av.scan

# Response
{
  "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "status": "malware",
  "detection": "EICAR-Test-File",
  ...
}
```

---

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": "error_code",
  "message": "Human-readable error description",
  "details": {
    "field": "additional context"
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_hash` | 400 | Hash format is invalid |
| `invalid_request` | 400 | Request body is malformed |
| `file_too_large` | 413 | File exceeds max_file_size |
| `job_not_found` | 404 | Job ID does not exist |
| `scanner_unavailable` | 503 | Scanner (ClamAV/Trivy) not available |
| `internal_error` | 500 | Unexpected server error |

---

## Rate Limiting

The HTTP API does not implement rate limiting by default. For production deployments, use a reverse proxy (nginx, Traefik) or API gateway for rate limiting.

---

## Authentication

The HTTP API does not implement authentication by default. For production:

1. Deploy behind an API gateway with authentication
2. Use network-level access controls
3. Implement custom middleware if needed

---

## SDK Examples

### Go Client

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "mime/multipart"
    "net/http"
    "os"
    "path/filepath"
)

const baseURL = "http://localhost:8080/api/v1"

// HashLookup performs a hash lookup
func HashLookup(hash string) (*LookupResult, error) {
    resp, err := http.Get(fmt.Sprintf("%s/files/%s", baseURL, hash))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result LookupResult
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    return &result, nil
}

// UploadFile uploads a file for scanning
func UploadFile(filePath string) (*UploadResponse, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    body := &bytes.Buffer{}
    writer := multipart.NewWriter(body)
    part, err := writer.CreateFormFile("file", filepath.Base(filePath))
    if err != nil {
        return nil, err
    }
    io.Copy(part, file)
    writer.Close()

    req, _ := http.NewRequest("POST", baseURL+"/files", body)
    req.Header.Set("Content-Type", writer.FormDataContentType())

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result UploadResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return &result, nil
}

// GetJob retrieves job status
func GetJob(jobID string) (*JobStatus, error) {
    resp, err := http.Get(fmt.Sprintf("%s/jobs/%s", baseURL, jobID))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var status JobStatus
    json.NewDecoder(resp.Body).Decode(&status)
    return &status, nil
}
```

### Python Client

```python
import requests
import time

BASE_URL = "http://localhost:8080/api/v1"

def hash_lookup(hash_value: str) -> dict:
    """Perform a hash lookup."""
    response = requests.get(f"{BASE_URL}/files/{hash_value}")
    response.raise_for_status()
    return response.json()

def upload_file(file_path: str) -> dict:
    """Upload a file for scanning."""
    with open(file_path, "rb") as f:
        response = requests.post(
            f"{BASE_URL}/files",
            files={"file": f}
        )
    response.raise_for_status()
    return response.json()

def wait_for_scan(job_id: str, timeout: int = 300) -> dict:
    """Wait for scan completion."""
    start = time.time()
    while time.time() - start < timeout:
        response = requests.get(f"{BASE_URL}/jobs/{job_id}")
        result = response.json()
        if result["status"] in ("completed", "failed"):
            return result
        time.sleep(1)
    raise TimeoutError("Scan did not complete in time")

# Usage
result = hash_lookup("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
print(f"Status: {result['status']}")

upload = upload_file("/path/to/file.exe")
if not upload.get("cached"):
    result = wait_for_scan(upload["job_id"])
    print(f"Scan result: {result['result']['status']}")
```

### cURL Examples

```bash
# Health check
curl -s http://localhost:8080/api/v1/health | jq

# Hash lookup
curl -s http://localhost:8080/api/v1/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f | jq

# Upload file
curl -s -X POST -F "file=@suspicious.exe" http://localhost:8080/api/v1/files | jq

# Get job status
curl -s http://localhost:8080/api/v1/jobs/job_abc123 | jq

# Dependency scan
curl -s -X POST http://localhost:8080/api/v1/dependencies/scan \
  -H "Content-Type: application/json" \
  -d '{"packages":[{"name":"requests","version":"2.25.0","ecosystem":"pip"}]}' | jq

# Poll dependency result
curl -s http://localhost:8080/api/v1/dependencies/jobs/trivy_job_xyz789 | jq
```
