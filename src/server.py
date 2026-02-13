"""
Sentinel Code - API Server
Direct analysis using analyzer.py (no OpenClaw)
"""

import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

from analyzer import CodeAnalyzer
from github_utils import GitHubUtils

app = Flask(__name__)
CORS(app)

analyzer = CodeAnalyzer()
github = GitHubUtils()

@app.route('/api/code/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "service": "sentinel-code",
        "version": "1.0.0"
    })

@app.route('/api/code/analyze', methods=['POST'])
def analyze_repo():
    """
    Analyze a GitHub repository
    Body: { "repo_url": "https://github.com/user/project" }
    """
    try:
        data = request.get_json()
        
        if not data or 'repo_url' not in data:
            return jsonify({"error": "repo_url is required"}), 400
        
        repo_url = data['repo_url']
        
        if not github.is_valid_github_url(repo_url):
            return jsonify({"error": "Invalid GitHub URL"}), 400
        
        # Clone repository
        repo_path = github.clone_repo(repo_url)
        
        if not repo_path:
            return jsonify({"error": "Failed to clone repository"}), 500
        
        # Analyze code
        result = analyzer.analyze(repo_path, repo_url)
        
        # Cleanup
        github.cleanup(repo_path)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8100))
    debug = os.getenv('DEBUG', 'false').lower() == 'true'
    
    print(f"Sentinel Code API starting on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
