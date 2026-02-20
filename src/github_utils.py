"""
GitHub Utilities - Clone, manage, and interact with GitHub repos
With Smart Sampling for prioritized file analysis
Enhanced with Solana/Anchor project detection and prioritization
"""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Optional

TEMP_DIR = os.path.join(os.path.dirname(__file__), '..', 'temp')


class GitHubUtils:

    # =========================================================================
    # FILE EXTENSIONS
    # =========================================================================
    
    EXTENSIONS = [
        '.py', '.js', '.ts', '.jsx', '.tsx',
        '.rs', '.sol', '.go', '.java',
        '.cpp', '.c', '.h', '.hpp',
        '.rb', '.php', '.swift', '.kt'
    ]

    # =========================================================================
    # DIRECTORIES TO SKIP
    # =========================================================================
    
    IGNORE_DIRS = [
        'node_modules', 'venv', '.venv', '__pycache__', '.git',
        'dist', 'build', 'target/debug', 'target/release', '.next', 
        'vendor', '.cache', 'coverage', '.nyc_output', 'eggs', 
        '.eggs', '*.egg-info', 'target/idl', 'target/types'
    ]

    # =========================================================================
    # PATTERNS TO SKIP
    # =========================================================================
    
    SKIP_PATTERNS = [
        'test_', '_test.', '.test.', 'spec_', '_spec.', '.spec.',
        'mock_', '_mock.', '.mock.', 'fixture', '__mocks__',
        'migrations', '.min.', '.bundle.', '.compiled.'
    ]

    # =========================================================================
    # GENERAL CRITICAL KEYWORDS (Non-Solana)
    # =========================================================================
    
    CRITICAL_KEYWORDS = [
        'auth', 'login', 'logout', 'password', 'credential', 'secret',
        'token', 'session', 'jwt', 'oauth', 'permission', 'role',
        'payment', 'checkout', 'billing', 'stripe', 'paypal',
        'admin', 'user', 'account', 'profile', 'register', 'signup',
        'api_key', 'private_key', 'encrypt', 'decrypt', 'hash'
    ]

    # =========================================================================
    # GENERAL IMPORTANT KEYWORDS (Non-Solana)
    # =========================================================================
    
    IMPORTANT_KEYWORDS = [
        'main', 'app', 'index', 'server', 'init', 'setup', 'config',
        'settings', 'database', 'db', 'model', 'schema', 'migrate',
        'api', 'route', 'router', 'controller', 'handler', 'view',
        'middleware', 'service', 'client', 'util', 'helper', 'core'
    ]

    # =========================================================================
    # GENERAL PRIORITY DIRECTORIES (Non-Solana)
    # =========================================================================
    
    PRIORITY_DIRS = [
        'src/', 'lib/', 'core/', 'api/', 'routes/', 'controllers/',
        'services/', 'models/', 'handlers/', 'middleware/', 'auth/',
        'app/', 'server/', 'backend/', 'pkg/', 'internal/'
    ]

    # =========================================================================
    # SOLANA-SPECIFIC CRITICAL KEYWORDS (Security-sensitive)
    # =========================================================================
    
    SOLANA_CRITICAL_KEYWORDS = [
        # Core program files
        'instruction', 'processor', 'entrypoint', 'program',
        # Security-sensitive operations
        'signer', 'authority', 'admin', 'owner', 'mint', 'vault', 'treasury',
        'withdraw', 'deposit', 'transfer', 'burn', 'close', 'initialize',
        # PDA related
        'pda', 'seeds', 'bump', 'find_program_address',
        # CPI related
        'cpi', 'invoke', 'invoke_signed',
        # Token operations
        'token', 'spl_token', 'associated_token', 'metadata', 'stake',
        # Access control
        'access', 'guard', 'constraint', 'validate', 'verify', 'check',
    ]

    # =========================================================================
    # SOLANA-SPECIFIC IMPORTANT KEYWORDS
    # =========================================================================
    
    SOLANA_IMPORTANT_KEYWORDS = [
        # Anchor framework
        'context', 'accounts', 'state', 'error', 'event',
        # Structure
        'lib', 'mod', 'handler', 'helper', 'util', 'constant',
        # Config
        'config', 'id', 'key', 'pubkey',
    ]

    # =========================================================================
    # SOLANA-SPECIFIC PRIORITY DIRECTORIES
    # =========================================================================
    
    SOLANA_PRIORITY_DIRS = [
        'programs/',
        'src/instructions/',
        'src/processor/',
        'src/state/',
        'src/contexts/',
        'src/handlers/',
        'src/errors/',
        'instructions/',
        'processor/',
        'state/',
        'contexts/',
    ]

    # =========================================================================
    # SOLANA PROJECT INDICATORS
    # =========================================================================
    
    SOLANA_INDICATOR_FILES = [
        'Anchor.toml',
        'Xargo.toml',
    ]
    
    SOLANA_CARGO_DEPS = [
        'anchor-lang',
        'anchor-spl',
        'solana-program',
        'solana-sdk',
        'spl-token',
        'spl-associated-token-account',
    ]
    
    SOLANA_CODE_PATTERNS = [
        'use anchor_lang::prelude::*',
        'use solana_program::',
        '#[program]',
        '#[derive(Accounts)]',
        'declare_id!',
        'entrypoint!',
        'solana_program::entrypoint',
    ]

    # =========================================================================
    # INITIALIZATION
    # =========================================================================
    
    def __init__(self):
        os.makedirs(TEMP_DIR, exist_ok=True)
        self._is_solana_project = None
        self._solana_framework = None

    # =========================================================================
    # URL VALIDATION
    # =========================================================================
    
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

    # =========================================================================
    # CLONE OPERATIONS
    # =========================================================================
    
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

            # Reset Solana detection cache for new repo
            self._is_solana_project = None
            self._solana_framework = None

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

    # =========================================================================
    # SOLANA PROJECT DETECTION
    # =========================================================================
    
    def detect_solana_project(self, repo_path: str) -> Tuple[bool, Optional[str]]:
        """
        Detect if repository is a Solana project and which framework it uses.
        
        Returns:
            Tuple of (is_solana, framework)
            framework can be: 'anchor', 'native', 'seahorse', or None
        """
        if self._is_solana_project is not None:
            return self._is_solana_project, self._solana_framework
        
        repo = Path(repo_path)
        is_solana = False
        framework = None
        
        # Check 1: Look for Anchor.toml (definitive Anchor project)
        if (repo / 'Anchor.toml').exists():
            is_solana = True
            framework = 'anchor'
            print(f"[Solana Detection] Found Anchor.toml -> Anchor project")
        
        # Check 2: Look for Cargo.toml with Solana dependencies
        cargo_toml = repo / 'Cargo.toml'
        if not is_solana and cargo_toml.exists():
            try:
                content = cargo_toml.read_text()
                for dep in self.SOLANA_CARGO_DEPS:
                    if dep in content:
                        is_solana = True
                        if 'anchor-lang' in content:
                            framework = 'anchor'
                        else:
                            framework = 'native'
                        print(f"[Solana Detection] Found {dep} in Cargo.toml -> {framework}")
                        break
            except:
                pass
        
        # Check 3: Look for programs/ directory with Cargo.toml inside
        programs_dir = repo / 'programs'
        if not is_solana and programs_dir.exists():
            for program in programs_dir.iterdir():
                if program.is_dir() and (program / 'Cargo.toml').exists():
                    is_solana = True
                    framework = 'anchor'  # programs/ dir is Anchor convention
                    print(f"[Solana Detection] Found programs/ directory -> Anchor project")
                    break
        
        # Check 4: Scan Rust files for Solana patterns
        if not is_solana:
            for rs_file in repo.rglob('*.rs'):
                try:
                    content = rs_file.read_text(errors='ignore')[:5000]
                    for pattern in self.SOLANA_CODE_PATTERNS:
                        if pattern in content:
                            is_solana = True
                            if 'anchor_lang' in content or '#[program]' in content:
                                framework = 'anchor'
                            elif 'entrypoint!' in content:
                                framework = 'native'
                            print(f"[Solana Detection] Found '{pattern}' in {rs_file.name}")
                            break
                    if is_solana:
                        break
                except:
                    pass
        
        # Check 5: Look for Seahorse (Python-based Solana)
        if not is_solana:
            for py_file in repo.rglob('*.py'):
                try:
                    content = py_file.read_text(errors='ignore')[:2000]
                    if 'from seahorse.prelude import' in content:
                        is_solana = True
                        framework = 'seahorse'
                        print(f"[Solana Detection] Found Seahorse import")
                        break
                except:
                    pass
        
        # Cache results
        self._is_solana_project = is_solana
        self._solana_framework = framework
        
        if is_solana:
            print(f"[Solana Detection] RESULT: Solana project ({framework})")
        else:
            print(f"[Solana Detection] RESULT: Not a Solana project")
        
        return is_solana, framework

    # =========================================================================
    # FILE FILTERING
    # =========================================================================
    
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

    # =========================================================================
    # FILE PRIORITY SCORING
    # =========================================================================
    
    def _get_priority(self, filepath: Path, is_solana: bool = False) -> int:
        """
        Score file by importance for security/quality analysis.
        Higher score = more important = analyzed first.
        
        Args:
            filepath: Path to the file
            is_solana: Whether this is a Solana project
        """
        name = filepath.name.lower()
        stem = filepath.stem.lower()
        path_str = str(filepath).lower()
        score = 0

        if is_solana:
            # =================================================================
            # SOLANA-SPECIFIC SCORING
            # =================================================================
            
            # CRITICAL: Solana security-sensitive files (+150)
            if any(kw in stem or kw in path_str for kw in self.SOLANA_CRITICAL_KEYWORDS):
                score += 150

            # HIGH: Solana important files (+75)
            if any(kw in stem for kw in self.SOLANA_IMPORTANT_KEYWORDS):
                score += 75

            # MEDIUM: Files in Solana priority directories (+50)
            if any(d in path_str for d in self.SOLANA_PRIORITY_DIRS):
                score += 50

            # BONUS: lib.rs is often the main entry point (+40)
            if name == 'lib.rs':
                score += 40

            # BONUS: mod.rs contains module structure (+20)
            if name == 'mod.rs':
                score += 20

            # BONUS: Rust files in Solana project (+30)
            if filepath.suffix == '.rs':
                score += 30

        else:
            # =================================================================
            # GENERAL (NON-SOLANA) SCORING
            # =================================================================
            
            # CRITICAL: Security-sensitive files (+100)
            if any(kw in stem or kw in path_str for kw in self.CRITICAL_KEYWORDS):
                score += 100

            # HIGH: Important entry points and core files (+50)
            if any(kw in stem for kw in self.IMPORTANT_KEYWORDS):
                score += 50

            # MEDIUM: Files in priority directories (+25)
            if any(d in path_str for d in self.PRIORITY_DIRS):
                score += 25

        # =====================================================================
        # UNIVERSAL SCORING (applies to all projects)
        # =====================================================================
        
        # BONUS: Larger files often contain more logic (+10/+20)
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

    # =========================================================================
    # FILE LIST RETRIEVAL
    # =========================================================================
    
    def get_file_list(self, repo_path: str, max_files: int = 50) -> list:
        """
        Get prioritized list of code files using smart sampling.
        
        For Solana projects:
        - Prioritizes instruction/processor/state files
        - Focuses on security-sensitive Rust code
        - Ignores compiled artifacts
        
        For other projects:
        - Prioritizes auth/payment/core files
        - Standard security-focused sampling
        """
        all_files = []
        repo = Path(repo_path)
        
        # Detect if Solana project
        is_solana, framework = self.detect_solana_project(repo_path)

        # Collect all code files
        for ext in self.EXTENSIONS:
            all_files.extend(repo.rglob(f'*{ext}'))

        # Filter out files that should be skipped
        filtered = [f for f in all_files if not self._should_skip(f)]

        # Sort by priority (highest first), passing Solana flag
        sorted_files = sorted(
            filtered, 
            key=lambda f: self._get_priority(f, is_solana), 
            reverse=True
        )

        # Log sampling info
        total = len(all_files)
        after_filter = len(filtered)
        selected = min(max_files, len(sorted_files))

        project_type = f"Solana ({framework})" if is_solana else "General"
        print(f"[Smart Sampling] Project: {project_type}")
        print(f"[Smart Sampling] {total} total → {after_filter} filtered → {selected} selected")

        # Log top priority files
        if sorted_files:
            print("[Smart Sampling] Top priority files:")
            for f in sorted_files[:5]:
                print(f"  [{self._get_priority(f, is_solana)}] {f.relative_to(repo)}")

        return sorted_files[:max_files]

    # =========================================================================
    # FILE READING
    # =========================================================================
    
    def read_file(self, file_path: str, max_lines: int = 500) -> str:
        """Read file content with line limit"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:max_lines]
                return ''.join(lines)
        except Exception as e:
            return f"Error reading file: {e}"

    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_sampling_stats(self, repo_path: str) -> dict:
        """Get statistics about file sampling for a repo"""
        all_files = []
        repo = Path(repo_path)
        
        is_solana, framework = self.detect_solana_project(repo_path)

        for ext in self.EXTENSIONS:
            all_files.extend(repo.rglob(f'*{ext}'))

        filtered = [f for f in all_files if not self._should_skip(f)]

        # Count by priority tier
        critical = [f for f in filtered if self._get_priority(f, is_solana) >= 100]
        high = [f for f in filtered if 50 <= self._get_priority(f, is_solana) < 100]
        medium = [f for f in filtered if 25 <= self._get_priority(f, is_solana) < 50]
        low = [f for f in filtered if self._get_priority(f, is_solana) < 25]

        return {
            "is_solana_project": is_solana,
            "framework": framework,
            "total_files": len(all_files),
            "after_filter": len(filtered),
            "skipped": len(all_files) - len(filtered),
            "critical_priority": len(critical),
            "high_priority": len(high),
            "medium_priority": len(medium),
            "low_priority": len(low)
        }
    
    # =========================================================================
    # SOLANA-SPECIFIC HELPERS
    # =========================================================================
    
    def get_program_names(self, repo_path: str) -> list:
        """Get list of Solana program names from programs/ directory"""
        programs = []
        programs_dir = Path(repo_path) / 'programs'
        
        if programs_dir.exists():
            for item in programs_dir.iterdir():
                if item.is_dir() and (item / 'Cargo.toml').exists():
                    programs.append(item.name)
        
        return programs
    
    def get_anchor_idl(self, repo_path: str) -> Optional[dict]:
        """Try to load Anchor IDL if available"""
        import json
        
        # Look for IDL in target/idl/
        idl_dir = Path(repo_path) / 'target' / 'idl'
        if idl_dir.exists():
            for idl_file in idl_dir.glob('*.json'):
                try:
                    with open(idl_file) as f:
                        return json.load(f)
                except:
                    pass
        
        return None
