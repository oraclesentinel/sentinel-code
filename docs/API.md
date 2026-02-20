# Sentinel Code API Documentation

**Version:** 2.1.0

## Base URL
```
https://oraclesentinel.xyz/api/code
```

Local development:
```
http://localhost:8100/api/code
```

## Authentication

Currently public API. Rate limits apply.

## Endpoints

### Health & Status

#### Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "ok",
  "service": "sentinel-code",
  "version": "2.1.0",
  "features": [
    "general_security_analysis",
    "solana_vulnerability_detection",
    "anchor_framework_support",
    "defi_protocol_analysis",
    "smart_file_sampling",
    "result_caching",
    "scan_history",
    "pdf_markdown_reports",
    "webhook_notifications",
    "scan_comparison"
  ],
  "cache_stats": {
    "active_entries": 5,
    "total_entries": 10,
    "total_hits": 42
  }
}
```

---

### Analysis

#### Full Analysis
```http
POST /analyze
```

Performs AI-powered security analysis on a GitHub repository.

**Request Body:**
```json
{
  "repo_url": "https://github.com/user/repository",
  "force_refresh": false,
  "cache_ttl": 24
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| repo_url | string | Yes | GitHub repository URL |
| force_refresh | boolean | No | Bypass cache (default: false) |
| cache_ttl | integer | No | Cache TTL in hours (default: 24) |

**Response:**
```json
{
  "repo": "https://github.com/user/repository",
  "scan_id": 123,
  "is_solana_project": true,
  "is_defi": false,
  "framework": "anchor",
  "score": 72,
  "files_analyzed": 15,
  "total_lines": 1250,
  "languages": {
    "Rust": 100
  },
  "programs_found": ["token_swap", "staking"],
  "critical": [
    {
      "id": "SOL-001",
      "title": "Missing Signer Check",
      "file": "programs/swap/src/lib.rs",
      "line": 45,
      "code": "pub authority: AccountInfo<'info>",
      "risk": "Anyone can call this instruction without authorization",
      "fix": "Add Signer constraint",
      "fix_code": "pub authority: Signer<'info>"
    }
  ],
  "warnings": [...],
  "improvements": [...],
  "summary": "Program has critical vulnerabilities that must be fixed.",
  "_cache": {
    "cached": false
  }
}
```

#### Quick Scan
```http
POST /scan
```

Fast project detection without AI analysis.

**Request Body:**
```json
{
  "repo_url": "https://github.com/user/repository"
}
```

**Response:**
```json
{
  "repo": "https://github.com/user/repository",
  "is_solana_project": true,
  "framework": "anchor",
  "programs": ["program_a", "program_b"],
  "stats": {
    "total_files": 50,
    "after_filter": 35,
    "skipped": 15,
    "critical_priority": 15,
    "high_priority": 10,
    "medium_priority": 5,
    "low_priority": 5
  }
}
```

---

### Cache Management

#### Get Cache Statistics
```http
GET /cache/stats
```

**Response:**
```json
{
  "active_entries": 5,
  "total_entries": 10,
  "total_hits": 42
}
```

#### Invalidate Cache
```http
POST /cache/invalidate
```

**Request Body:**
```json
{
  "repo_url": "https://github.com/user/repository"
}
```

**Response:**
```json
{
  "invalidated": true,
  "repo": "https://github.com/user/repository"
}
```

#### Cleanup Expired Cache
```http
POST /cache/cleanup
```

**Response:**
```json
{
  "deleted": 5
}
```

---

### Scan History

#### Get History
```http
GET /history?repo_url=...&limit=20
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| repo_url | string | No | Filter by repository |
| limit | integer | No | Max results (default: 20) |

**Response:**
```json
{
  "history": [
    {
      "id": 123,
      "repo_url": "https://github.com/user/repo",
      "is_solana_project": true,
      "framework": "anchor",
      "score": 72,
      "critical_count": 2,
      "warning_count": 5,
      "improvement_count": 8,
      "files_analyzed": 15,
      "total_lines": 1250,
      "scanned_at": "2026-02-20 04:30:00"
    }
  ],
  "count": 1
}
```

#### Get Specific Scan
```http
GET /history/{scan_id}
```

**Response:**
```json
{
  "id": 123,
  "repo_url": "https://github.com/user/repo",
  "scanned_at": "2026-02-20 04:30:00",
  "result": {
    // Full scan result
  }
}
```

#### Get Score Trend
```http
GET /history/trend?repo_url=...&limit=10
```

**Response:**
```json
{
  "repo": "https://github.com/user/repo",
  "trend": [
    {"id": 1, "score": 50, "critical_count": 5, "scanned_at": "2026-02-18"},
    {"id": 2, "score": 65, "critical_count": 3, "scanned_at": "2026-02-19"},
    {"id": 3, "score": 72, "critical_count": 2, "scanned_at": "2026-02-20"}
  ],
  "data_points": 3
}
```

---

### Scan Comparison

#### Compare Two Scans
```http
GET /compare?old_scan_id=1&new_scan_id=2
```

**Response:**
```json
{
  "old_scan": {
    "id": 1,
    "scanned_at": "2026-02-18",
    "score": 50,
    "critical_count": 5,
    "warning_count": 8
  },
  "new_scan": {
    "id": 2,
    "scanned_at": "2026-02-20",
    "score": 72,
    "critical_count": 2,
    "warning_count": 5
  },
  "comparison": {
    "score_change": 22,
    "score_improved": true,
    "fixed_critical": 3,
    "new_critical": 0,
    "fixed_warnings": 3,
    "new_warnings": 0,
    "fixed_critical_list": ["file.rs:45:SOL-001", ...],
    "new_critical_list": []
  },
  "summary": "Score improved by 22 points. 3 critical issue(s) fixed. Great progress!"
}
```

#### Compare Latest Scans
```http
GET /compare/latest?repo_url=...
```

Compares the two most recent scans for a repository.

---

### Reports

#### PDF Report
```http
GET /report/pdf/{scan_id}
```

Returns a PDF file with professional security audit report.

**Response:** `application/pdf`

#### Markdown Report
```http
GET /report/markdown/{scan_id}
```

Returns a Markdown-formatted report.

**Response:** `text/markdown`

#### Comparison Report
```http
GET /report/comparison/{old_scan_id}/{new_scan_id}
```

Returns a Markdown comparison report between two scans.

---

### Webhooks

#### List Webhooks
```http
GET /webhooks?active_only=true
```

**Response:**
```json
{
  "webhooks": [
    {
      "id": 1,
      "name": "CI Pipeline",
      "url": "https://example.com/webhook",
      "events": ["scan_complete", "critical_found"],
      "repo_filter": null,
      "active": true,
      "trigger_count": 15,
      "last_triggered": "2026-02-20 04:30:00",
      "created_at": "2026-02-15 10:00:00"
    }
  ]
}
```

#### Create Webhook
```http
POST /webhooks
```

**Request Body:**
```json
{
  "name": "CI Pipeline",
  "url": "https://example.com/webhook",
  "secret": "your-hmac-secret",
  "events": ["scan_complete", "critical_found", "score_improved", "score_decreased"],
  "repo_filter": "my-org/my-repo"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Webhook name |
| url | string | Yes | Webhook endpoint URL |
| secret | string | No | HMAC-SHA256 secret for signing |
| events | array | No | Events to trigger (default: scan_complete) |
| repo_filter | string | No | Only trigger for matching repos |

**Available Events:**
- `scan_complete` - After every scan
- `critical_found` - When critical issues are found
- `score_improved` - When score increases
- `score_decreased` - When score decreases

**Response:**
```json
{
  "id": 1,
  "name": "CI Pipeline",
  "url": "https://example.com/webhook",
  "events": ["scan_complete", "critical_found"],
  "created": true
}
```

#### Get Webhook
```http
GET /webhooks/{id}
```

#### Update Webhook
```http
PUT /webhooks/{id}
```

**Request Body:**
```json
{
  "name": "Updated Name",
  "active": false
}
```

#### Delete Webhook
```http
DELETE /webhooks/{id}
```

#### Test Webhook
```http
POST /webhooks/{id}/test
```

Sends a test ping to the webhook endpoint.

**Response:**
```json
{
  "success": true,
  "webhook_id": 1,
  "webhook_name": "CI Pipeline",
  "url": "https://example.com/webhook"
}
```

#### Get Webhook Logs
```http
GET /webhooks/{id}/logs?limit=50
```

**Response:**
```json
{
  "logs": [
    {
      "id": 1,
      "webhook_id": 1,
      "event": "scan_complete",
      "response_code": 200,
      "success": true,
      "triggered_at": "2026-02-20 04:30:00"
    }
  ]
}
```

#### Webhook Payload

All webhook payloads include:
```json
{
  "event": "scan_complete",
  "scan_id": 123,
  "repo": "https://github.com/user/repo",
  "is_solana_project": true,
  "framework": "anchor",
  "score": 72,
  "summary": {
    "critical_count": 2,
    "warning_count": 5,
    "improvement_count": 8,
    "files_analyzed": 15
  },
  "timestamp": "2026-02-20T04:30:00Z"
}
```

**Webhook Headers:**
```
Content-Type: application/json
User-Agent: SentinelCode-Webhook/2.0
X-Sentinel-Event: scan_complete
X-Sentinel-Delivery: 1708408200.123
X-Sentinel-Signature: sha256=abc123...
```

**Verifying Signatures (Node.js):**
```javascript
const crypto = require('crypto');

function verifySignature(payload, signature, secret) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}
```

---

### Vulnerability Reference

#### List All Vulnerabilities
```http
GET /vulnerabilities
```

**Response:**
```json
{
  "solana": {
    "critical": [
      {"id": "SOL-001", "title": "Missing Signer Check", "severity": "CRITICAL", "description": "..."},
      ...
    ],
    "warnings": [...],
    "improvements": [...]
  },
  "defi": [
    {"id": "DEFI-001", "title": "Flash Loan Price Manipulation", "severity": "CRITICAL", "category": "flash_loan", "description": "..."},
    ...
  ],
  "general": {
    "critical": ["SQL Injection", "XSS", ...],
    "warnings": [...],
    "improvements": [...]
  }
}
```

---

## Error Responses

All errors return JSON:
```json
{
  "error": "Error message description"
}
```

| HTTP Code | Description |
|-----------|-------------|
| 400 | Bad request (invalid URL, missing parameters) |
| 404 | Resource not found (scan, webhook) |
| 500 | Server error (clone failed, analysis error) |
| 504 | Timeout (repository too large) |

---

## Rate Limits

| Tier | Requests/minute | Requests/hour |
|------|-----------------|---------------|
| Free | 10 | 100 |
| $OSAI Holder (1000+) | Unlimited | Unlimited |

---

## Changelog

### v2.1.0 (2026-02-20)
- Added Solana/Anchor vulnerability detection (15+ checks)
- Added DeFi protocol analysis (14 checks)
- Added result caching with configurable TTL
- Added scan history and comparison
- Added PDF and Markdown report generation
- Added webhook notifications for CI/CD
- Added score trend tracking

### v1.0.0 (2026-02-13)
- Initial release
- General code security analysis
- Basic API endpoints
