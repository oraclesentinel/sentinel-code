"""
Code Analyzer - AI-powered code analysis using Claude
Enhanced with Solana/Anchor vulnerability detection + DeFi patterns
Part of Sentinel Code - Oracle Sentinel Intelligence Layer
"""

import os
import json
import re
import requests
from pathlib import Path
from github_utils import GitHubUtils
from solana_defi_patterns import DEFI_CHECKLIST, is_defi_project

OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', '')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# =============================================================================
# GENERAL ANALYSIS PROMPT (Non-Solana projects)
# =============================================================================

GENERAL_ANALYSIS_PROMPT = '''You are Sentinel Code, an AI-powered code security analyzer. Analyze the provided codebase and generate a detailed security and quality report.

## IMPORTANT RULES
1. EVERY issue MUST have file path and line number
2. EVERY issue MUST show the actual code snippet
3. EVERY issue MUST have a concrete fix with code example
4. Do NOT use vague descriptions
5. Be SPECIFIC - list exact locations
6. Return ONLY valid JSON, no markdown or extra text

## ANALYSIS CATEGORIES

### CRITICAL (Severity: High - Must fix before production)
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Hardcoded secrets/credentials
- Authentication bypass
- Insecure deserialization
- Path traversal

### WARNINGS (Severity: Medium - Should fix)
- Missing input validation
- Weak cryptography
- Information disclosure
- Missing error handling
- Insecure configurations
- Missing rate limiting

### IMPROVEMENTS (Severity: Low - Best practices)
- Missing type hints
- Missing documentation
- Code duplication
- Performance issues
- Missing tests

## SCORING GUIDE
- Start at 100 points
- Each CRITICAL issue: -15 points
- Each WARNING: -5 points
- Each IMPROVEMENT suggestion does not reduce score
- Minimum score: 0

## OUTPUT FORMAT (JSON)

Return ONLY this JSON structure:
{{
  "scan_type": "general",
  "score": <0-100 security score>,
  "summary": "<2-3 sentence summary>",
  "critical": [
    {{
      "id": "GEN-001",
      "title": "<Issue title>",
      "file": "<path/to/file.py>",
      "line": <line number>,
      "code": "<vulnerable code snippet>",
      "risk": "<what is dangerous>",
      "fix": "<how to fix>",
      "fix_code": "<corrected code>"
    }}
  ],
  "warnings": [
    {{
      "id": "GEN-101",
      "title": "<Warning title>",
      "file": "<path/to/file.py>",
      "line": <line number>,
      "code": "<problematic code>",
      "issue": "<what is the problem>",
      "fix": "<solution>",
      "fix_code": "<improved code>"
    }}
  ],
  "improvements": [
    {{
      "id": "GEN-201",
      "title": "<Improvement title>",
      "file": "<path/to/file.py>",
      "line": <line number>,
      "current": "<current code>",
      "suggested": "<improved code>",
      "benefit": "<why this is better>"
    }}
  ]
}}

Now analyze this codebase:

Repository: {repo_url}

{files_content}
'''

# =============================================================================
# SOLANA/ANCHOR ANALYSIS PROMPT (Base)
# =============================================================================

SOLANA_ANALYSIS_PROMPT = '''You are Sentinel Code, an expert Solana/Anchor security auditor. Analyze the provided Solana program for security vulnerabilities.

## SOLANA VULNERABILITY CHECKLIST

### CRITICAL VULNERABILITIES (Must check all)

1. **Missing Signer Check (SOL-001)**
   - Does every privileged instruction verify the signer?
   - Look for: AccountInfo without Signer<> constraint
   - Look for: Missing `#[account(signer)]` or `Signer<'info>`

2. **Missing Owner Check (SOL-002)**
   - Are account owners validated?
   - Look for: `AccountInfo<'info>` without owner validation
   - Look for: `/// CHECK:` comments without proper validation
   - Look for: `UncheckedAccount` usage

3. **Arbitrary CPI (SOL-003)**
   - Is the target program validated before CPI?
   - Look for: `invoke()` or `invoke_signed()` with unvalidated program
   - Look for: Missing `Program<'info, T>` type constraint

4. **PDA Validation Missing (SOL-004)**
   - Are PDAs properly derived and verified?
   - Look for: Missing `seeds = [...]` constraint
   - Look for: Missing `bump` validation
   - Look for: PDA used without re-derivation

5. **Integer Overflow/Underflow (SOL-005)**
   - Is arithmetic checked for overflow?
   - Look for: `+`, `-`, `*` without `checked_add`, `checked_sub`, `checked_mul`
   - Look for: Token amount calculations without overflow protection

6. **Account Data Matching (SOL-006)**
   - Are related accounts validated against each other?
   - Look for: Missing `has_one` constraints
   - Look for: Missing `constraint = ` checks
   - Look for: Accounts that should be related but aren't validated

7. **Type Cosplay (SOL-007)**
   - Can accounts be confused with different types?
   - Look for: Manual deserialization without discriminator check
   - Look for: `try_from_slice` on AccountInfo data

8. **Improper Account Closing (SOL-008)**
   - Are accounts closed safely?
   - Look for: Manual lamport zeroing without data clearing
   - Look for: Missing `#[account(close = destination)]`
   - Look for: Accounts that can be revived after closing

### WARNING VULNERABILITIES

9. **Missing Rent Exemption (SOL-101)**
   - Are new accounts rent-exempt?
   - Look for: Account creation without rent check

10. **Duplicate Mutable Accounts (SOL-102)**
    - Can same account be passed twice as mutable?
    - Look for: Multiple `#[account(mut)]` that could be same account

11. **Missing Bump Seed (SOL-103)**
    - Is PDA bump stored for efficiency?
    - Look for: `find_program_address` called repeatedly

12. **Sysvar Spoofing (SOL-105)**
    - Are sysvars properly typed?
    - Look for: `AccountInfo` for Clock, Rent instead of `Sysvar<>`

### IMPROVEMENTS

13. **Use Anchor Constraints (SOL-201)**
    - Replace manual checks with declarative constraints

14. **Add Custom Error Codes (SOL-202)**
    - Use descriptive errors instead of generic ones

15. **Add Event Logging (SOL-204)**
    - Emit events for important state changes

{defi_checklist}

## SCORING GUIDE
- Start at 100 points
- Each CRITICAL issue: -15 points
- Each WARNING: -5 points
- Each IMPROVEMENT suggestion does not reduce score
- Minimum score: 0

## IMPORTANT RULES
1. EVERY issue MUST have file path and line number
2. EVERY issue MUST show the actual vulnerable code
3. EVERY issue MUST have a concrete fix with Anchor/Solana code
4. Use the SOL-XXX or DEFI-XXX IDs from the checklist above
5. Return ONLY valid JSON, no markdown

## OUTPUT FORMAT (JSON)

Return ONLY this JSON structure:
{{
  "scan_type": "solana",
  "is_defi": {is_defi},
  "framework": "{framework}",
  "programs_found": [<list of program names if any>],
  "score": <0-100 security score>,
  "summary": "<2-3 sentence Solana-specific summary>",
  "critical": [
    {{
      "id": "SOL-001",
      "title": "Missing Signer Check",
      "file": "programs/myprogram/src/lib.rs",
      "line": 45,
      "code": "pub authority: AccountInfo<'info>",
      "risk": "Anyone can call this instruction without authorization",
      "fix": "Add Signer constraint to authority account",
      "fix_code": "pub authority: Signer<'info>"
    }}
  ],
  "warnings": [
    {{
      "id": "SOL-101",
      "title": "<Warning title>",
      "file": "<path>",
      "line": <number>,
      "code": "<problematic code>",
      "issue": "<problem description>",
      "fix": "<solution>",
      "fix_code": "<improved code>"
    }}
  ],
  "improvements": [
    {{
      "id": "SOL-201",
      "title": "<Improvement title>",
      "file": "<path>",
      "line": <number>,
      "current": "<current code>",
      "suggested": "<improved code>",
      "benefit": "<why better>"
    }}
  ]
}}

Now analyze this Solana program:

Repository: {repo_url}
Framework: {framework}

{files_content}
'''


class CodeAnalyzer:
    """
    AI-powered code analyzer with Solana/Anchor specialization.
    
    Features:
    - Auto-detects Solana projects
    - Auto-detects DeFi protocols for extended checks
    - Uses specialized prompts for Solana security
    - Returns structured JSON results
    - Calculates security scores
    """
    
    def __init__(self):
        self.github = GitHubUtils()
        self.model = "anthropic/claude-sonnet-4.6"

    def analyze(self, repo_path: str, repo_url: str) -> dict:
        """
        Analyze a cloned repository.
        
        Auto-detects if Solana project and uses appropriate analysis.
        For DeFi projects, includes additional vulnerability checks.
        """
        # Detect project type
        is_solana, framework = self.github.detect_solana_project(repo_path)
        
        # Get prioritized file list
        files = self.github.get_file_list(repo_path)

        if not files:
            return {
                "error": "No code files found", 
                "repo": repo_url,
                "is_solana_project": is_solana
            }

        # Read file contents
        file_contents = {}
        total_lines = 0
        language_stats = {}
        all_content = ""  # For DeFi detection

        for f in files[:30]:  # Limit to top 30 files
            rel_path = str(f.relative_to(repo_path))
            content = self.github.read_file(str(f))
            file_contents[rel_path] = content
            all_content += content + "\n"
            lines = content.count('\n')
            total_lines += lines
            ext = f.suffix
            language_stats[ext] = language_stats.get(ext, 0) + lines

        # Calculate language percentages
        languages = {}
        for ext, lines in language_stats.items():
            pct = round((lines / total_lines) * 100) if total_lines > 0 else 0
            languages[self._ext_to_language(ext)] = pct
        languages = dict(sorted(languages.items(), key=lambda x: x[1], reverse=True))

        # Build files text for prompt
        files_text = ""
        for path, content in file_contents.items():
            lines = content.split('\n')[:200]  # Limit lines per file
            files_text += f"\n\n=== FILE: {path} ===\n" + '\n'.join(lines)

        # Detect if DeFi project
        is_defi = False
        if is_solana:
            is_defi = is_defi_project(all_content)
            print(f"[Analyzer] DeFi detection: {is_defi}")

        # Run AI analysis with appropriate prompt
        if is_solana:
            print(f"[Analyzer] Using Solana analysis prompt (framework: {framework}, defi: {is_defi})")
            analysis_result = self._ai_analyze_solana(files_text, repo_url, framework, is_defi)
        else:
            print(f"[Analyzer] Using general analysis prompt")
            analysis_result = self._ai_analyze_general(files_text, repo_url)

        # Build response
        response = {
            "repo": repo_url,
            "is_solana_project": is_solana,
            "is_defi": is_defi,
            "framework": framework,
            "files_analyzed": len(file_contents),
            "total_lines": total_lines,
            "languages": languages,
        }
        
        # Merge analysis result
        if isinstance(analysis_result, dict):
            response.update(analysis_result)
        else:
            # If parsing failed, include raw analysis
            response["analysis"] = analysis_result
            response["parse_error"] = True
        
        # Add program names for Solana projects
        if is_solana:
            programs = self.github.get_program_names(repo_path)
            if programs:
                response["programs_found"] = programs

        return response

    def _ext_to_language(self, ext: str) -> str:
        """Map file extension to language name"""
        mapping = {
            '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript',
            '.jsx': 'React JSX', '.tsx': 'React TSX', '.rs': 'Rust',
            '.sol': 'Solidity', '.go': 'Go', '.java': 'Java',
            '.cpp': 'C++', '.c': 'C', '.h': 'C Header',
        }
        return mapping.get(ext, ext)

    def _ai_analyze_general(self, files_content: str, repo_url: str) -> dict:
        """Run general (non-Solana) analysis"""
        prompt = GENERAL_ANALYSIS_PROMPT.format(
            repo_url=repo_url, 
            files_content=files_content
        )
        return self._call_ai(prompt)

    def _ai_analyze_solana(self, files_content: str, repo_url: str, 
                           framework: str, is_defi: bool) -> dict:
        """Run Solana-specific analysis with optional DeFi checks"""
        
        # Include DeFi checklist if it's a DeFi project
        defi_checklist = DEFI_CHECKLIST if is_defi else ""
        
        prompt = SOLANA_ANALYSIS_PROMPT.format(
            repo_url=repo_url,
            framework=framework or 'unknown',
            is_defi=str(is_defi).lower(),
            defi_checklist=defi_checklist,
            files_content=files_content
        )
        return self._call_ai(prompt)

    def _call_ai(self, prompt: str) -> dict:
        """Call OpenRouter API and parse JSON response"""
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
                    "temperature": 0.2  # Lower temperature for more consistent output
                },
                timeout=180  # Increased timeout for complex analysis
            )

            if response.status_code != 200:
                return {"error": f"API error: {response.status_code}", "raw": response.text}

            data = response.json()
            content = data["choices"][0]["message"]["content"]
            
            # Parse JSON from response
            return self._parse_json_response(content)
            
        except requests.Timeout:
            return {"error": "Analysis timeout - repository may be too large"}
        except Exception as e:
            return {"error": f"Analysis error: {str(e)}"}

    def _parse_json_response(self, content: str) -> dict:
        """
        Parse JSON from AI response.
        Handles markdown code blocks and various formats.
        """
        # Try direct JSON parse first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON from markdown code block
        json_patterns = [
            r'```json\s*([\s\S]*?)\s*```',
            r'```\s*([\s\S]*?)\s*```',
            r'\{[\s\S]*\}',
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, content)
            if match:
                try:
                    json_str = match.group(1) if '```' in pattern else match.group(0)
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    continue
        
        # If all parsing fails, return structured error with raw content
        return {
            "parse_error": True,
            "raw_analysis": content,
            "score": 0,
            "critical": [],
            "warnings": [],
            "improvements": []
        }

    def get_vulnerability_stats(self, result: dict) -> dict:
        """Get statistics from analysis result"""
        return {
            "critical_count": len(result.get("critical", [])),
            "warning_count": len(result.get("warnings", [])),
            "improvement_count": len(result.get("improvements", [])),
            "score": result.get("score", 0),
            "is_solana": result.get("is_solana_project", False),
            "is_defi": result.get("is_defi", False),
            "framework": result.get("framework"),
        }
