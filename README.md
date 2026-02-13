# Sentinel Code

AI-Powered Code Analysis for Developers

Part of [Oracle Sentinel](https://oraclesentinel.xyz) Intelligence Layer

## Overview

Sentinel Code analyzes GitHub repositories using AI to detect:

- **Security vulnerabilities** - SQL injection, XSS, hardcoded secrets
- **Bug risks** - Null pointers, race conditions, unhandled exceptions
- **Code quality issues** - Missing error handling, no input validation
- **Improvements** - Type hints, documentation, tests

## Quick Start

### Installation
```bash
git clone https://github.com/oraclesentinel/sentinel-code.git
cd sentinel-code
pip install -r requirements.txt
cp .env.example .env
# Add your OpenRouter API key to .env
```

### Run Server
```bash
cd src
python server.py
```

### API Usage
```bash
curl -X POST http://localhost:8100/api/code/analyze \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/project"}'
```

## Project Structure
```
sentinel-code/
├── src/
│   ├── server.py        # Flask API server
│   ├── analyzer.py      # AI code analysis
│   └── github_utils.py  # Git operations
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

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/code/health` | GET | Health check |
| `/api/code/analyze` | POST | Analyze repository |

## Response Format
```json
{
  "repo": "https://github.com/user/project",
  "score": 72,
  "files_analyzed": 15,
  "languages": {"Python": 85, "JavaScript": 15},
  "critical": [...],
  "warnings": [...],
  "improvements": [...],
  "summary": "Brief assessment"
}
```

## Pricing

- **$0.10** per analysis
- **FREE** for $OSAI holders (1000+)

## Links

- Website: [oraclesentinel.xyz](https://oraclesentinel.xyz)
- Code Analysis: [oraclesentinel.xyz/code](https://oraclesentinel.xyz/code)
- Twitter: [@oracle_sentinel](https://twitter.com/oracle_sentinel)

## Token

**$OSAI** - Powers all Oracle Sentinel intelligence modules
```
Contract: HuDBwWRsa4bu8ueaCb7PPgJrqBeZDkcyFqMW5bbXpump
Network: Solana
```

## License

MIT License
