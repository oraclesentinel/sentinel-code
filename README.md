# Sentinel Code

AI-Powered Code Analysis for GitHub Repositories

Part of [Oracle Sentinel](https://oraclesentinel.xyz) Intelligence Layer

## Overview

Sentinel Code analyzes any public GitHub repository using AI to detect:

- **Security vulnerabilities** - SQL injection, XSS, hardcoded secrets, auth issues
- **Bug risks** - Null pointers, race conditions, unhandled exceptions
- **Code quality issues** - Missing error handling, no input validation
- **Improvements** - Type hints, documentation, tests

## Live Demo

Try it now: [oraclesentinel.xyz/code](https://oraclesentinel.xyz/code)

## Features

- Analyze any public GitHub repository
- AI-powered detection using Claude
- Detailed reports with file locations and line numbers
- Code snippets showing problematic code
- Recommended fixes with corrected code examples
- Quality score (0-100)

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

### API Usage
```bash
curl -X POST http://localhost:8100/api/code/analyze \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repository"}'
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/code/health` | GET | Health check |
| `/api/code/analyze` | POST | Analyze repository |

## Response Format
```json
{
  "repo": "https://github.com/user/project",
  "files_analyzed": 15,
  "total_lines": 1250,
  "languages": {
    "Python": 85,
    "JavaScript": 15
  },
  "score": 72,
  "critical": [
    {
      "title": "SQL Injection Risk",
      "file": "src/db.py",
      "line": 45,
      "code": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
      "risk": "User input directly interpolated into SQL query",
      "fix": "Use parameterized queries",
      "fix_code": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"
    }
  ],
  "warnings": [...],
  "improvements": [...],
  "summary": "Code has some security issues that should be addressed."
}
```

## Project Structure
```
sentinel-code/
├── src/
│   ├── server.py        # Flask API server
│   ├── analyzer.py      # AI code analysis engine
│   └── github_utils.py  # Git clone and file operations
├── docs/
│   └── API.md           # API documentation
├── tests/
│   └── test_analyzer.py # Unit tests
├── examples/
│   └── sample_output.json
├── requirements.txt
├── .env.example
└── README.md
```

## How It Works

1. **Clone** - Repository is cloned with `--depth 1` for speed
2. **Scan** - Files are scanned (Python, JavaScript, TypeScript, Rust, Go, Solidity)
3. **Analyze** - AI analyzes code for security, bugs, and quality issues
4. **Report** - Structured JSON report with issues, fixes, and score

## Supported Languages

- Python (.py)
- JavaScript (.js)
- TypeScript (.ts)
- React (.jsx, .tsx)
- Rust (.rs)
- Go (.go)
- Solidity (.sol)
- Java (.java)
- C/C++ (.c, .cpp, .h)
- Ruby (.rb)
- PHP (.php)

## Links

- **Website:** [oraclesentinel.xyz](https://oraclesentinel.xyz)
- **Code Analysis:** [oraclesentinel.xyz/code](https://oraclesentinel.xyz/code)
- **Twitter:** [@oracle_sentinel](https://x.com/oracle_sentinel)
- **Telegram:** [t.me/oraclesentinelsignals](https://t.me/oraclesentinelsignals)

## Part of Oracle Sentinel

Sentinel Code is one module in the Oracle Sentinel Intelligence Hub:

| Module | Status | Description |
|--------|--------|-------------|
| **Predict** | Live | Polymarket prediction analysis |
| **Code** | Live | GitHub code analysis |
| **Trust** | Soon | Token/project trust scoring |

## License

MIT License - see [LICENSE](LICENSE)
