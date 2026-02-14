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

ANALYSIS_PROMPT = '''You are Sentinel Code, an AI-powered code analyzer. Analyze the provided codebase and generate a detailed security and quality report.

## IMPORTANT RULES
1. EVERY issue MUST have file path and line number
2. EVERY issue MUST show the actual code snippet
3. EVERY issue MUST have a concrete fix with code example
4. Do NOT use vague descriptions
5. Be SPECIFIC - list exact locations

## OUTPUT FORMAT:

ORACLE SENTINEL CODE REVIEW

Repo: {repo_url}
Language: <languages with percentages>
Files analyzed: <count>

---

CRITICAL ISSUES (<count>)

1. <Issue Title>
   File: <path/file.py>:<line>
   Code: <code snippet>
   Risk: <what is dangerous>
   Fix: <how to fix with code>

(repeat for each critical issue, or "No critical issues found" if none)

---

WARNINGS (<count>)

1. <Warning Title>
   File: <path/file.py>:<line>
   Code: <code snippet>
   Issue: <problem>
   Fix: <solution with code>

(repeat for each warning)

---

IMPROVEMENTS (<count>)

1. <Improvement Title>
   File: <path/file.py>:<line>
   Current: <current code>
   Suggested: <improved code>
   Benefit: <why better>

(repeat for each improvement)

---

Now analyze this codebase:

Repository: {repo_url}

{files_content}
'''

class CodeAnalyzer:
    def __init__(self):
        self.github = GitHubUtils()
        self.model = "anthropic/claude-sonnet-4.5"
    
    def analyze(self, repo_path: str, repo_url: str) -> dict:
        """Analyze a cloned repository"""
        
        files = self.github.get_file_list(repo_path)
        
        if not files:
            return {"error": "No code files found", "repo": repo_url}
        
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
        
        languages = {}
        for ext, lines in language_stats.items():
            pct = round((lines / total_lines) * 100) if total_lines > 0 else 0
            languages[self._ext_to_language(ext)] = pct
        languages = dict(sorted(languages.items(), key=lambda x: x[1], reverse=True))
        
        files_text = ""
        for path, content in file_contents.items():
            lines = content.split('\n')[:200]
            files_text += f"\n\n=== FILE: {path} ===\n" + '\n'.join(lines)
        
        analysis = self._ai_analyze(files_text, repo_url)
        
        return {
            "repo": repo_url,
            "files_analyzed": len(file_contents),
            "total_lines": total_lines,
            "languages": languages,
            "analysis": analysis
        }
    
    def _ext_to_language(self, ext: str) -> str:
        mapping = {
            '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript',
            '.jsx': 'React JSX', '.tsx': 'React TSX', '.rs': 'Rust',
            '.sol': 'Solidity', '.go': 'Go', '.java': 'Java',
            '.cpp': 'C++', '.c': 'C', '.h': 'C Header',
        }
        return mapping.get(ext, ext)
    
    def _ai_analyze(self, files_content: str, repo_url: str) -> str:
        prompt = ANALYSIS_PROMPT.format(repo_url=repo_url, files_content=files_content)
        
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
                    "max_tokens": 16000,
                    "temperature": 0.3
                },
                timeout=120
            )
            
            if response.status_code != 200:
                return f"Analysis failed: {response.status_code}"
            
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            return f"Analysis error: {str(e)}"
