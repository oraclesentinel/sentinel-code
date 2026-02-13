"""
Code Analyzer - AI-powered code analysis using Claude
"""

import os
import json
import requests
from pathlib import Path
from github_utils import GitHubUtils

OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', '')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

class CodeAnalyzer:
    def __init__(self):
        self.github = GitHubUtils()
        self.model = "anthropic/claude-sonnet-4.5"
    
    def analyze(self, repo_path: str, repo_url: str) -> dict:
        """Analyze a cloned repository"""
        
        files = self.github.get_file_list(repo_path)
        
        if not files:
            return {
                "error": "No code files found",
                "score": 0,
                "repo": repo_url
            }
        
        # Read file contents
        file_contents = {}
        total_lines = 0
        language_stats = {}
        
        for f in files[:30]:
            rel_path = str(f.relative_to(repo_path))
            content = self.github.read_file(str(f))
            file_contents[rel_path] = content
            
            lines = content.count('\n')
            total_lines += lines
            
            ext = f.suffix
            language_stats[ext] = language_stats.get(ext, 0) + lines
        
        # Calculate language percentages
        languages = {}
        for ext, lines in language_stats.items():
            pct = round((lines / total_lines) * 100) if total_lines > 0 else 0
            lang_name = self._ext_to_language(ext)
            languages[lang_name] = pct
        
        languages = dict(sorted(languages.items(), key=lambda x: x[1], reverse=True))
        
        # AI Analysis
        analysis = self._ai_analyze(file_contents, repo_url)
        
        # Build report
        report = {
            "repo": repo_url,
            "files_analyzed": len(file_contents),
            "total_lines": total_lines,
            "languages": languages,
            "score": analysis.get("score", 50),
            "critical": analysis.get("critical", []),
            "warnings": analysis.get("warnings", []),
            "improvements": analysis.get("improvements", []),
            "summary": analysis.get("summary", "")
        }
        
        return report
    
    def _ext_to_language(self, ext: str) -> str:
        mapping = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.jsx': 'React JSX',
            '.tsx': 'React TSX',
            '.rs': 'Rust',
            '.sol': 'Solidity',
            '.go': 'Go',
            '.java': 'Java',
            '.cpp': 'C++',
            '.c': 'C',
            '.h': 'C Header',
            '.rb': 'Ruby',
            '.php': 'PHP',
        }
        return mapping.get(ext, ext)
    
    def _ai_analyze(self, file_contents: dict, repo_url: str) -> dict:
        """Send code to AI for analysis"""
        
        files_text = ""
        for path, content in file_contents.items():
            files_text += f"\n\n=== FILE: {path} ===\n{content[:3000]}"
        
        prompt = f"""Analyze this codebase for security and quality issues.

Repository: {repo_url}

{files_text}

Return a JSON object with this EXACT structure:
{{
    "score": <number 0-100>,
    "critical": [
        {{
            "title": "Issue title",
            "file": "path/to/file.py",
            "line": 142,
            "code": "problematic code snippet (max 3 lines)",
            "risk": "What is dangerous about this",
            "fix": "How to fix it",
            "fix_code": "corrected code snippet"
        }}
    ],
    "warnings": [
        {{
            "title": "Warning title",
            "file": "path/to/file.py",
            "line": 50,
            "code": "code snippet",
            "issue": "What is the problem",
            "fix": "How to fix",
            "fix_code": "fixed code"
        }}
    ],
    "improvements": [
        {{
            "title": "Improvement title",
            "file": "path/to/file.py",
            "line": 20,
            "current": "current code",
            "suggested": "improved code",
            "benefit": "Why this is better"
        }}
    ],
    "summary": "Brief 1-2 sentence assessment"
}}

Focus on:
1. Security: SQL injection, XSS, hardcoded secrets, auth issues
2. Bugs: null pointers, race conditions, unhandled exceptions
3. Quality: error handling, input validation, logging
4. Improvements: type hints, documentation, tests

Be specific with file paths and line numbers. Return ONLY valid JSON, no markdown."""

        try:
            response = requests.post(
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 4000,
                    "temperature": 0.2
                },
                timeout=120
            )
            
            if response.status_code != 200:
                print(f"AI API error: {response.status_code}")
                return {"score": 50, "summary": "Analysis failed"}
            
            data = response.json()
            content = data['choices'][0]['message']['content']
            
            # Clean JSON
            content = content.strip()
            if content.startswith('```'):
                content = content.split('\n', 1)[1]
                content = content.rsplit('```', 1)[0]
            
            result = json.loads(content)
            return result
            
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
            return {"score": 50, "summary": "Failed to parse analysis"}
        except Exception as e:
            print(f"AI analysis error: {e}")
            return {"score": 50, "summary": f"Analysis error: {str(e)}"}
