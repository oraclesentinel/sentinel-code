# Sentinel Code API Documentation

## Base URL
```
https://oraclesentinel.xyz/api/code
```

## Endpoints

### Health Check
```
GET /health
```

**Response:**
```json
{
  "status": "ok",
  "service": "sentinel-code",
  "version": "1.0.0"
}
```

### Analyze Repository
```
POST /analyze
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
  "repo": "https://github.com/user/repository",
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
      "fix_code": "query = \"SELECT * FROM users WHERE id = ?\"\ncursor.execute(query, (user_id,))"
    }
  ],
  "warnings": [...],
  "improvements": [...],
  "summary": "Code has some security issues that should be addressed."
}
```

## Pricing

| Action | Price | $OSAI Holder (1000+) |
|--------|-------|---------------------|
| Analyze | $0.10 | FREE |

## Rate Limits

- 10 requests per minute
- 100 requests per hour

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Invalid GitHub URL |
| 500 | Clone or analysis failed |
| 504 | Analysis timeout |
