"""
GitHub Utilities - Clone, manage, and interact with GitHub repos
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

TEMP_DIR = os.path.join(os.path.dirname(__file__), '..', 'temp')

class GitHubUtils:
    def __init__(self):
        # Ensure temp directory exists
        os.makedirs(TEMP_DIR, exist_ok=True)
    
    def is_valid_github_url(self, url: str) -> bool:
        """Validate GitHub repository URL"""
        pattern = r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+/?$'
        return bool(re.match(pattern, url))
    
    def extract_repo_info(self, url: str) -> tuple:
        """Extract owner and repo name from URL"""
        # Remove trailing slash and .git
        url = url.rstrip('/').replace('.git', '')
        parts = url.split('/')
        owner = parts[-2]
        repo = parts[-1]
        return owner, repo
    
    def clone_repo(self, repo_url: str) -> str:
        """
        Clone a GitHub repository to temp directory
        Returns path to cloned repo or None if failed
        """
        try:
            owner, repo = self.extract_repo_info(repo_url)
            repo_path = os.path.join(TEMP_DIR, f"{owner}_{repo}")
            
            # Remove if already exists
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            
            # Clone with depth 1 (shallow clone for speed)
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
    
    def get_file_list(self, repo_path: str, extensions: list = None) -> list:
        """
        Get list of code files in repository
        
        Default extensions: .py, .js, .ts, .rs, .sol, .go, .java, .cpp, .c, .h
        """
        if extensions is None:
            extensions = [
                '.py', '.js', '.ts', '.jsx', '.tsx',
                '.rs', '.sol', '.go', '.java',
                '.cpp', '.c', '.h', '.hpp',
                '.rb', '.php', '.swift', '.kt'
            ]
        
        files = []
        repo = Path(repo_path)
        
        for ext in extensions:
            files.extend(repo.rglob(f'*{ext}'))
        
        # Filter out common non-essential directories
        ignore_dirs = ['node_modules', 'venv', '.venv', '__pycache__', 
                       '.git', 'dist', 'build', 'target', '.next']
        
        filtered = []
        for f in files:
            path_str = str(f)
            if not any(d in path_str for d in ignore_dirs):
                filtered.append(f)
        
        return filtered
    
    def read_file(self, file_path: str, max_lines: int = 500) -> str:
        """Read file content with line limit"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:max_lines]
                return ''.join(lines)
        except Exception as e:
            return f"Error reading file: {e}"
