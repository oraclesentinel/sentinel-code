"""
GitHub Utilities - Clone, manage, and interact with GitHub repos
With Smart Sampling for prioritized file analysis
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

TEMP_DIR = os.path.join(os.path.dirname(__file__), '..', 'temp')

class GitHubUtils:
    
    # File extensions to analyze
    EXTENSIONS = [
        '.py', '.js', '.ts', '.jsx', '.tsx',
        '.rs', '.sol', '.go', '.java',
        '.cpp', '.c', '.h', '.hpp',
        '.rb', '.php', '.swift', '.kt'
    ]
    
    # Directories to always skip
    IGNORE_DIRS = [
        'node_modules', 'venv', '.venv', '__pycache__', '.git',
        'dist', 'build', 'target', '.next', 'vendor', '.cache',
        'coverage', '.nyc_output', 'eggs', '.eggs', '*.egg-info'
    ]
    
    # Patterns to skip (test files, mocks, etc)
    SKIP_PATTERNS = [
        'test_', '_test.', '.test.', 'spec_', '_spec.', '.spec.',
        'mock_', '_mock.', '.mock.', 'fixture', '__mocks__',
        'migrations', '.min.', '.bundle.', '.compiled.'
    ]
    
    # Critical files for security analysis (highest priority)
    CRITICAL_KEYWORDS = [
        'auth', 'login', 'logout', 'password', 'credential', 'secret',
        'token', 'session', 'jwt', 'oauth', 'permission', 'role',
        'payment', 'checkout', 'billing', 'stripe', 'paypal',
        'admin', 'user', 'account', 'profile', 'register', 'signup',
        'api_key', 'private_key', 'encrypt', 'decrypt', 'hash'
    ]
    
    # Important entry points and core files (high priority)
    IMPORTANT_KEYWORDS = [
        'main', 'app', 'index', 'server', 'init', 'setup', 'config',
        'settings', 'database', 'db', 'model', 'schema', 'migrate',
        'api', 'route', 'router', 'controller', 'handler', 'view',
        'middleware', 'service', 'client', 'util', 'helper', 'core'
    ]
    
    # Priority directories (files in these get bonus)
    PRIORITY_DIRS = [
        'src/', 'lib/', 'core/', 'api/', 'routes/', 'controllers/',
        'services/', 'models/', 'handlers/', 'middleware/', 'auth/',
        'app/', 'server/', 'backend/', 'pkg/', 'internal/'
    ]
    
    def __init__(self):
        os.makedirs(TEMP_DIR, exist_ok=True)
    
    def is_valid_github_url(self, url: str) -> bool:
        """Validate GitHub repository URL"""
        pattern = r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+/?$'
        return bool(re.match(pattern, url))
    
    def extract_repo_info(self, url: str) -> tuple:
        """Extract owner and repo name from URL"""
        url = url.rstrip('/').replace('.git', '')
        parts = url.split('/')
        owner = parts[-2]
        repo = parts[-1]
        return owner, repo
    
    def clone_repo(self, repo_url: str) -> str:
        """Clone a GitHub repository to temp directory"""
        try:
            owner, repo = self.extract_repo_info(repo_url)
            repo_path = os.path.join(TEMP_DIR, f"{owner}_{repo}")
            
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repo_url, repo_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                print(f"Clone error: {result.stderr}")
                return None
            
            return repo_path
            
        except subprocess.TimeoutExpired:
            print("Clone timeout")
            return None
        except Exception as e:
            print(f"Clone exception: {e}")
            return None
    
    def cleanup(self, repo_path: str):
        """Remove cloned repository"""
        try:
            if repo_path and os.path.exists(repo_path):
                shutil.rmtree(repo_path)
        except Exception as e:
            print(f"Cleanup error: {e}")
    
    def _should_skip(self, filepath: Path) -> bool:
        """Check if file should be skipped"""
        name = filepath.name.lower()
        path_str = str(filepath).lower()
        
        # Skip files in ignored directories
        if any(d in path_str for d in self.IGNORE_DIRS):
            return True
        
        # Skip test/mock files
        if any(p in name or p in path_str for p in self.SKIP_PATTERNS):
            return True
        
        return False
    
    def _get_priority(self, filepath: Path) -> int:
        """
        Score file by importance for security/quality analysis
        Higher score = more important = analyzed first
        """
        name = filepath.name.lower()
        stem = filepath.stem.lower()  # filename without extension
        path_str = str(filepath).lower()
        score = 0
        
        # CRITICAL: Security-sensitive files (+100)
        if any(kw in stem or kw in path_str for kw in self.CRITICAL_KEYWORDS):
            score += 100
        
        # HIGH: Important entry points and core files (+50)
        if any(kw in stem for kw in self.IMPORTANT_KEYWORDS):
            score += 50
        
        # MEDIUM: Files in priority directories (+25)
        if any(d in path_str for d in self.PRIORITY_DIRS):
            score += 25
        
        # BONUS: Larger files often contain more logic (+10)
        try:
            size = filepath.stat().st_size
            if size > 5000:  # > 5KB
                score += 10
            if size > 10000:  # > 10KB
                score += 10
        except:
            pass
        
        # BONUS: Root-level files are often important (+15)
        if str(filepath.parent).count('/') <= 2:
            score += 15
        
        return score
    
    def get_file_list(self, repo_path: str, max_files: int = 50) -> list:
        """
        Get prioritized list of code files using smart sampling
        
        1. Collects all code files
        2. Filters out test/mock/vendor files
        3. Sorts by priority (security-critical first)
        4. Returns top N files
        """
        all_files = []
        repo = Path(repo_path)
        
        # Collect all code files
        for ext in self.EXTENSIONS:
            all_files.extend(repo.rglob(f'*{ext}'))
        
        # Filter out files that should be skipped
        filtered = [f for f in all_files if not self._should_skip(f)]
        
        # Sort by priority (highest first)
        sorted_files = sorted(filtered, key=lambda f: self._get_priority(f), reverse=True)
        
        # Log sampling info
        total = len(all_files)
        after_filter = len(filtered)
        selected = min(max_files, len(sorted_files))
        
        print(f"Smart Sampling: {total} total → {after_filter} filtered → {selected} selected")
        
        # Log top priority files
        if sorted_files:
            print("Top priority files:")
            for f in sorted_files[:5]:
                print(f"  [{self._get_priority(f)}] {f.name}")
        
        return sorted_files[:max_files]
    
    def read_file(self, file_path: str, max_lines: int = 500) -> str:
        """Read file content with line limit"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:max_lines]
                return ''.join(lines)
        except Exception as e:
            return f"Error reading file: {e}"
    
    def get_sampling_stats(self, repo_path: str) -> dict:
        """Get statistics about file sampling for a repo"""
        all_files = []
        repo = Path(repo_path)
        
        for ext in self.EXTENSIONS:
            all_files.extend(repo.rglob(f'*{ext}'))
        
        filtered = [f for f in all_files if not self._should_skip(f)]
        
        # Count by priority tier
        critical = [f for f in filtered if self._get_priority(f) >= 100]
        high = [f for f in filtered if 50 <= self._get_priority(f) < 100]
        medium = [f for f in filtered if 25 <= self._get_priority(f) < 50]
        low = [f for f in filtered if self._get_priority(f) < 25]
        
        return {
            "total_files": len(all_files),
            "after_filter": len(filtered),
            "skipped": len(all_files) - len(filtered),
            "critical_priority": len(critical),
            "high_priority": len(high),
            "medium_priority": len(medium),
            "low_priority": len(low)
        }
