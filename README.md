# Sentinel Code

**AI-Powered Security Analysis for Solana/Anchor Programs & General Codebases**

Part of [Oracle Sentinel](https://oraclesentinel.xyz) Intelligence Layer

[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](https://github.com/oraclesentinel/sentinel-code)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

Sentinel Code is a specialized security scanner that uses AI to detect vulnerabilities in codebases, with deep expertise in **Solana/Anchor programs** and **DeFi protocols**.

### Key Features

- **Solana/Anchor Specialization** - Detects 15+ Solana-specific vulnerabilities
- **DeFi Protocol Analysis** - 14 additional checks for AMMs, lending, staking, oracles
- **Auto-Detection** - Automatically identifies Solana projects and frameworks
- **Smart File Sampling** - Prioritizes security-critical files
- **Result Caching** - Saves API costs with configurable TTL
- **Scan History** - Track security improvements over time
- **PDF/Markdown Reports** - Professional audit reports
- **Webhook Notifications** - CI/CD integration support

## Try It

Scan your repository now: [code.oraclesentinel.xyz](https://code.oraclesentinel.xyz)

## Solana Vulnerability Detection

### Critical Vulnerabilities (SOL-001 to SOL-008)

| ID | Vulnerability | Description |
|----|--------------|-------------|
| SOL-001 | Missing Signer Check | Instruction doesn't verify account signatures |
| SOL-002 | Missing Owner Check | Account owner not validated |
| SOL-003 | Arbitrary CPI | Cross-program invocation without program validation |
| SOL-004 | PDA Validation Missing | PDA not properly derived/verified |
| SOL-005 | Integer Overflow | Arithmetic without checked operations |
| SOL-006 | Account Data Matching | Related accounts not validated against each other |
| SOL-007 | Type Cosplay | Accounts can be confused with different types |
| SOL-008 | Improper Account Closing | Accounts closed incorrectly, can be revived |

### Warnings (SOL-101 to SOL-105)

| ID | Warning | Description |
|----|---------|-------------|
| SOL-101 | Missing Rent Exemption | New accounts may not be rent-exempt |
| SOL-102 | Duplicate Mutable Accounts | Same account passed twice as mutable |
| SOL-103 | Missing Bump Seed | PDA bump not stored for efficiency |
| SOL-105 | Sysvar Spoofing | Sysvars not properly typed |

### DeFi-Specific Checks (DEFI-001 to DEFI-014)

| ID | Category | Vulnerability |
|----|----------|--------------|
| DEFI-001 | Flash Loan | Price manipulation via flash loans |
| DEFI-002 | Flash Loan | Reentrancy in callbacks |
| DEFI-003 | AMM/DEX | Missing slippage protection |
| DEFI-004 | AMM/DEX | Constant product invariant not enforced |
| DEFI-005 | Lending | Incorrect liquidation threshold |
| DEFI-006 | Lending | Interest rate manipulation |
| DEFI-007 | Lending | Improper bad debt handling |
| DEFI-008 | Staking | Incorrect reward calculation (precision loss) |
| DEFI-009 | Staking | First depositor front-running |
| DEFI-010 | Oracle | Stale oracle price |
| DEFI-011 | Oracle | Single oracle source |
| DEFI-012 | Governance | Flash loan voting attack |
| DEFI-013 | Governance | Timelock bypass |
| DEFI-014 | Vault | Share inflation attack |

## Quick Start

### Installation
```bash
git clone https://github.com/oraclesentinel/sentinel-code.git
cd sentinel-code
pip install -r requirements.txt
cp .env.example .env
```

Add your OpenRouter API key to `.env`:
```
OPENROUTER_API_KEY=your_api_key_here
```

### Run Server
```bash
cd src
python server.py
```

Server starts at `http://localhost:8100`

### Basic Usage
```bash
# Analyze a Solana repository
curl -X POST http://localhost:8100/api/code/analyze \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/coral-xyz/anchor"}'
```

## API Reference

### Base URL
```
https://oraclesentinel.xyz/api/code
```

### Core Endpoints

#### Health Check
```
GET /health
```

**Response:**
```json
{
  "status": "ok",
  "service": "sentinel-code",
  "version": "2.1.0",
  "features": ["solana_vulnerability_detection", "defi_protocol_analysis", ...],
  "cache_stats": {"active_entries": 5, "total_hits": 42}
}
```

#### Analyze Repository
```
POST /analyze
```

**Request:**
```json
{
  "repo_url": "https://github.com/user/solana-program",
  "force_refresh": false,
  "cache_ttl": 24
}
```

**Response:**
```json
{
  "repo": "https://github.com/user/solana-program",
  "scan_id": 123,
  "is_solana_project": true,
  "is_defi": true,
  "framework": "anchor",
  "score": 72,
  "files_analyzed": 15,
  "total_lines": 1250,
  "languages": {"Rust": 100},
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
  "_cache": {"cached": false}
}
```

#### Quick Scan (No AI)
```
POST /scan
```

Fast project detection without full analysis.

**Request:**
```json
{
  "repo_url": "https://github.com/user/solana-program"
}
```

**Response:**
```json
{
  "repo": "...",
  "is_solana_project": true,
  "framework": "anchor",
  "programs": ["program_a", "program_b"],
  "stats": {
    "total_files": 50,
    "critical_priority": 15,
    "high_priority": 10
  }
}
```

### History & Comparison

#### Get Scan History
```
GET /history?repo_url=...&limit=20
```

#### Get Specific Scan
```
GET /history/{scan_id}
```

#### Get Score Trend
```
GET /history/trend?repo_url=...&limit=10
```

#### Compare Two Scans
```
GET /compare?old_scan_id=1&new_scan_id=2
```

**Response:**
```json
{
  "old_scan": {"id": 1, "score": 50, "critical_count": 5},
  "new_scan": {"id": 2, "score": 75, "critical_count": 2},
  "comparison": {
    "score_change": 25,
    "score_improved": true,
    "fixed_critical": 3,
    "new_critical": 0
  },
  "summary": "Score improved by 25 points. 3 critical issues fixed."
}
```

#### Compare Latest Scans
```
GET /compare/latest?repo_url=...
```

### Reports

#### Download PDF Report
```
GET /report/pdf/{scan_id}
```

Returns a professional PDF security audit report.

#### Download Markdown Report
```
GET /report/markdown/{scan_id}
```

Returns a Markdown-formatted report.

#### Comparison Report
```
GET /report/comparison/{old_id}/{new_id}
```

### Cache Management

#### Get Cache Stats
```
GET /cache/stats
```

#### Invalidate Cache
```
POST /cache/invalidate
Body: {"repo_url": "..."}
```

#### Cleanup Expired Cache
```
POST /cache/cleanup
```

### Webhooks (CI/CD Integration)

#### List Webhooks
```
GET /webhooks
```

#### Create Webhook
```
POST /webhooks
```

**Request:**
```json
{
  "name": "CI Pipeline",
  "url": "https://your-ci.com/webhook",
  "secret": "hmac-secret",
  "events": ["scan_complete", "critical_found", "score_improved", "score_decreased"],
  "repo_filter": "my-org/my-repo"
}
```

#### Test Webhook
```
POST /webhooks/{id}/test
```

#### Get Webhook Logs
```
GET /webhooks/{id}/logs
```

#### Update/Delete Webhook
```
PUT /webhooks/{id}
DELETE /webhooks/{id}
```

**Webhook Payload Example:**
```json
{
  "event": "scan_complete",
  "scan_id": 123,
  "repo": "https://github.com/user/repo",
  "score": 72,
  "summary": {
    "critical_count": 2,
    "warning_count": 5
  },
  "timestamp": "2026-02-20T04:30:00Z"
}
```

Webhooks include HMAC-SHA256 signature in `X-Sentinel-Signature` header.

### Vulnerability Reference

#### List All Detectable Vulnerabilities
```
GET /vulnerabilities
```

## Project Structure
```
sentinel-code/
├── src/
│   ├── server.py              # Flask API server (v2.1)
│   ├── analyzer.py            # AI analysis engine
│   ├── github_utils.py        # Git operations & smart sampling
│   ├── database.py            # SQLite: cache, history, webhooks
│   ├── report_generator.py    # PDF & Markdown reports
│   ├── webhook_service.py     # Webhook notifications
│   ├── solana_patterns.py     # Solana vulnerability database
│   └── solana_defi_patterns.py # DeFi vulnerability database
├── data/
│   └── sentinel_code.db       # SQLite database
├── reports/                   # Generated reports
├── docs/
│   └── API.md
├── tests/
├── requirements.txt
└── README.md
```

## How It Works

1. **Clone** - Repository cloned with `--depth 1`
2. **Detect** - Auto-detect Solana/Anchor/DeFi project type
3. **Sample** - Smart sampling prioritizes security-critical files
4. **Analyze** - AI analysis with specialized vulnerability checklist
5. **Report** - Structured JSON with issues, fixes, and score
6. **Cache** - Results cached for 24h (configurable)
7. **Notify** - Webhooks triggered for CI/CD integration

## Supported Languages

| Language | Extensions | Solana Support |
|----------|------------|----------------|
| Rust | .rs | ✅ Full (Anchor/Native) |
| Solidity | .sol | ✅ Basic |
| Python | .py | ✅ General |
| JavaScript | .js | ✅ General |
| TypeScript | .ts, .tsx | ✅ General |
| Go | .go | ✅ General |
| Java | .java | ✅ General |
| C/C++ | .c, .cpp, .h | ✅ General |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | API key for Claude | Required |
| `PORT` | Server port | 8100 |
| `DEBUG` | Debug mode | false |

## Links

- **Website:** [oraclesentinel.xyz](https://oraclesentinel.xyz)
- **Sentinel Code:** [code.oraclesentinel.xyz](https://code.oraclesentinel.xyz)
- **Twitter:** [@oracle_sentinel](https://x.com/oracle_sentinel)
- **Telegram:** [t.me/oraclesentinelsignals](https://t.me/oraclesentinelsignals)

## Part of Oracle Sentinel

| Module | Status | Description |
|--------|--------|-------------|
| **Sentinel Predict** | ✅ Live | Polymarket prediction analysis |
| **Sentinel Code** | ✅ Live | GitHub security analysis |
| **Sentinel Economic** | ✅ Live | API marketplace |

## Contributing

Contributions welcome! Feel free to open issues or pull requests.

## License

MIT License - see [LICENSE](LICENSE)

---

**Built for the Solana ecosystem** 🦀
