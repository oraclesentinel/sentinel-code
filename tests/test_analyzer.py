"""
Unit tests for Sentinel Code analyzer
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from github_utils import GitHubUtils

class TestGitHubUtils(unittest.TestCase):
    
    def setUp(self):
        self.github = GitHubUtils()
    
    def test_valid_github_url(self):
        valid_urls = [
            "https://github.com/user/repo",
            "https://github.com/user-name/repo-name",
            "https://github.com/user/repo123",
        ]
        for url in valid_urls:
            self.assertTrue(self.github.is_valid_github_url(url), f"Should be valid: {url}")
    
    def test_invalid_github_url(self):
        invalid_urls = [
            "https://gitlab.com/user/repo",
            "http://github.com/user/repo",
            "github.com/user/repo",
            "https://github.com/user",
            "random string",
        ]
        for url in invalid_urls:
            self.assertFalse(self.github.is_valid_github_url(url), f"Should be invalid: {url}")
    
    def test_extract_repo_info(self):
        url = "https://github.com/oraclesentinel/oracle-sentinel"
        owner, repo = self.github.extract_repo_info(url)
        self.assertEqual(owner, "oraclesentinel")
        self.assertEqual(repo, "oracle-sentinel")

if __name__ == '__main__':
    unittest.main()
