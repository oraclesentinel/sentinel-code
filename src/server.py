"""
Sentinel Code - API Server v2.1
AI-powered code analysis with Solana/Anchor/DeFi specialization
Features: Caching, History, Reports, Webhooks, Comparisons
Part of Oracle Sentinel Intelligence Layer
"""

import os
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
from dotenv import load_dotenv
from io import BytesIO

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

from analyzer import CodeAnalyzer
from github_utils import GitHubUtils
from database import db
from report_generator import report_generator
from webhook_service import webhook_service

# x402 PayAI Payment Handler
from x402_handler import init_x402, get_x402_info, get_payment_requirements, verify_and_settle_payment
from rate_limiter import rate_limiter, get_client_ip

app = Flask(__name__)
CORS(app)

# Setup x402 PayAI payment middleware
init_x402()

analyzer = CodeAnalyzer()
github = GitHubUtils()

# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.route('/api/code/health', methods=['GET'])
def health():
    """Health check endpoint"""
    cache_stats = db.get_cache_stats()
    
    return jsonify({
        "status": "ok",
        "service": "sentinel-code",
        "version": "2.2.0",
        "features": [
            "general_security_analysis",
            "solana_vulnerability_detection",
            "anchor_framework_support",
            "defi_protocol_analysis",
            "smart_file_sampling",
            "result_caching",
            "scan_history",
            "pdf_markdown_reports",
            "webhook_notifications",
            "scan_comparison",
            "x402_paid_scan"
        ],
        "cache_stats": cache_stats,
        "x402": get_x402_info()
    })

# =============================================================================
# MAIN ANALYSIS ENDPOINT
# =============================================================================

@app.route('/api/code/analyze', methods=['POST'])
def analyze_repo():
    """
    Analyze a GitHub repository for security vulnerabilities.
    
    Features:
    - Auto-detects Solana/Anchor projects
    - Auto-detects DeFi protocols for extended checks
    - Caches results (default 24h TTL)
    - Saves to history
    - Triggers webhooks
    
    Request Body:
        {
            "repo_url": "https://github.com/user/project",
            "force_refresh": false,  // Optional: bypass cache
            "cache_ttl": 24          // Optional: cache TTL in hours
        }
    
    Response:
        {
            "repo": "...",
            "is_solana_project": true/false,
            "is_defi": true/false,
            "framework": "anchor/native/null",
            "score": 0-100,
            "critical": [...],
            "warnings": [...],
            "improvements": [...],
            "scan_id": 123,
            "_cache": { "cached": true/false, ... }
        }
    """
    try:
        # Rate limit check for free tier
        client_ip = get_client_ip(request)
        allowed, remaining, reset_in = rate_limiter.is_allowed(client_ip)
        
        # Check for x402 payment header
        payment_header = request.headers.get('X-PAYMENT')
        
        if not allowed and not payment_header:
            # No quota left and no payment - return 402 with payment requirements
            import base64
            import json
            payment_req = get_payment_requirements()
            payment_req_encoded = base64.b64encode(json.dumps(payment_req).encode()).decode()
            
            response = jsonify({
                "error": "Free tier exhausted. Payment required for additional scans.",
                "rate_limit": {
                    "limit": 3,
                    "remaining": 0,
                    "reset_in_seconds": reset_in,
                    "reset_in_hours": round(reset_in / 3600, 1)
                },
                "x402": {
                    "price": "$0.01 USDC",
                    "network": "solana-mainnet",
                    "instruction": "Add X-PAYMENT header with signed payment to continue"
                }
            })
            response.headers['PAYMENT-REQUIRED'] = payment_req_encoded
            return response, 402
        
        # If payment provided, verify and settle
        is_paid_scan = False
        if payment_header and not allowed:
            print(f"[x402] Verifying payment from {client_ip}...")
            payment_result = verify_and_settle_payment(payment_header)
            
            if not payment_result.get('success'):
                return jsonify({
                    "error": "Payment verification failed",
                    "reason": payment_result.get('error')
                }), 402
            
            print(f"[x402] Payment verified! Payer: {payment_result.get('payer')}")
            is_paid_scan = True


        data = request.get_json()

        if not data or 'repo_url' not in data:
            return jsonify({"error": "repo_url is required"}), 400

        repo_url = data['repo_url']
        force_refresh = data.get('force_refresh', False)
        cache_ttl = data.get('cache_ttl', 24)

        if not github.is_valid_github_url(repo_url):
            return jsonify({"error": "Invalid GitHub URL"}), 400

        # Check cache first (unless force_refresh)
        if not force_refresh:
            cached = db.get_cached_scan(repo_url)
            if cached:
                print(f"[Server] Cache hit for {repo_url}")
                return jsonify(cached)

        # Clone repository
        print(f"[Server] Cloning {repo_url}")
        repo_path = github.clone_repo(repo_url)

        if not repo_path:
            return jsonify({"error": "Failed to clone repository"}), 500

        # Get previous scan for comparison
        previous_scans = db.get_scan_history(repo_url, limit=1)
        previous_score = previous_scans[0]['score'] if previous_scans else None

        # Analyze code
        print(f"[Server] Analyzing repository...")
        result = analyzer.analyze(repo_path, repo_url)

        # Cleanup cloned repo
        github.cleanup(repo_path)

        # Save to history
        scan_id = db.save_scan_history(repo_url, result)
        result['scan_id'] = scan_id
        
        # Record successful scan for rate limiting
        rate_limiter.record_request(client_ip)
        print(f"[Server] Saved as scan #{scan_id}")

        # Cache result
        db.cache_scan(repo_url, result, ttl_hours=cache_ttl)

        # Get stats
        stats = analyzer.get_vulnerability_stats(result)
        print(f"[Server] Analysis complete: {stats}")

        # Trigger webhooks
        try:
            webhook_service.trigger_scan_complete(result, scan_id)
            
            # Check for score change
            if previous_score is not None:
                current_score = result.get('score', 0)
                if current_score != previous_score:
                    webhook_service.trigger_score_changed(
                        repo_url, previous_score, current_score, scan_id
                    )
        except Exception as e:
            print(f"[Server] Webhook error (non-fatal): {e}")

        return jsonify(result)

    except Exception as e:
        print(f"[Server] Error: {e}")
        return jsonify({"error": str(e)}), 500

# =============================================================================
# QUICK SCAN ENDPOINT
# =============================================================================

@app.route('/api/code/scan', methods=['POST'])
def quick_scan():
    """
    Quick scan - detect project type and get file stats.
    No AI analysis, much faster.
    """
    try:
        data = request.get_json()

        if not data or 'repo_url' not in data:
            return jsonify({"error": "repo_url is required"}), 400

        repo_url = data['repo_url']

        if not github.is_valid_github_url(repo_url):
            return jsonify({"error": "Invalid GitHub URL"}), 400

        repo_path = github.clone_repo(repo_url)
        if not repo_path:
            return jsonify({"error": "Failed to clone repository"}), 500

        is_solana, framework = github.detect_solana_project(repo_path)
        stats = github.get_sampling_stats(repo_path)
        programs = github.get_program_names(repo_path) if is_solana else []

        github.cleanup(repo_path)

        return jsonify({
            "repo": repo_url,
            "is_solana_project": is_solana,
            "framework": framework,
            "programs": programs,
            "stats": stats
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# CACHE MANAGEMENT
# =============================================================================

@app.route('/api/code/cache/invalidate', methods=['POST'])
def invalidate_cache():
    """Invalidate cache for a specific repo"""
    try:
        data = request.get_json()
        repo_url = data.get('repo_url')
        
        if not repo_url:
            return jsonify({"error": "repo_url is required"}), 400
        
        success = db.invalidate_cache(repo_url)
        return jsonify({"invalidated": success, "repo": repo_url})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/code/cache/cleanup', methods=['POST'])
def cleanup_cache():
    """Remove all expired cache entries"""
    try:
        deleted = db.cleanup_expired_cache()
        return jsonify({"deleted": deleted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/code/cache/stats', methods=['GET'])
def cache_stats():
    """Get cache statistics"""
    return jsonify(db.get_cache_stats())

# =============================================================================
# SCAN HISTORY
# =============================================================================

@app.route('/api/code/history', methods=['GET'])
def get_history():
    """
    Get scan history.
    
    Query params:
        repo_url: Optional filter by repo
        limit: Number of results (default 20)
    """
    repo_url = request.args.get('repo_url')
    limit = int(request.args.get('limit', 20))
    
    history = db.get_scan_history(repo_url, limit)
    return jsonify({"history": history, "count": len(history)})

@app.route('/api/code/history/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get full scan result by ID"""
    scan = db.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)

@app.route('/api/code/history/trend', methods=['GET'])
def get_trend():
    """
    Get score trend for a repo.
    
    Query params:
        repo_url: Required
        limit: Number of data points (default 10)
    """
    repo_url = request.args.get('repo_url')
    if not repo_url:
        return jsonify({"error": "repo_url is required"}), 400
    
    limit = int(request.args.get('limit', 10))
    trend = db.get_repo_trend(repo_url, limit)
    
    return jsonify({
        "repo": repo_url,
        "trend": trend,
        "data_points": len(trend)
    })

# =============================================================================
# SCAN COMPARISON
# =============================================================================

@app.route('/api/code/compare', methods=['GET'])
def compare_scans():
    """
    Compare two scans.
    
    Query params:
        old_scan_id: ID of older scan
        new_scan_id: ID of newer scan
    """
    old_id = request.args.get('old_scan_id', type=int)
    new_id = request.args.get('new_scan_id', type=int)
    
    if not old_id or not new_id:
        return jsonify({"error": "old_scan_id and new_scan_id are required"}), 400
    
    comparison = db.compare_scans(old_id, new_id)
    return jsonify(comparison)

@app.route('/api/code/compare/latest', methods=['GET'])
def compare_latest():
    """
    Compare latest two scans for a repo.
    
    Query params:
        repo_url: Required
    """
    repo_url = request.args.get('repo_url')
    if not repo_url:
        return jsonify({"error": "repo_url is required"}), 400
    
    history = db.get_scan_history(repo_url, limit=2)
    if len(history) < 2:
        return jsonify({"error": "Need at least 2 scans to compare"}), 400
    
    comparison = db.compare_scans(history[1]['id'], history[0]['id'])
    return jsonify(comparison)

# =============================================================================
# REPORT GENERATION
# =============================================================================

@app.route('/api/code/report/markdown/<int:scan_id>', methods=['GET'])
def get_markdown_report(scan_id):
    """Generate and return Markdown report for a scan"""
    scan = db.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    markdown_content = report_generator.generate_markdown(scan['result'])
    
    return Response(
        markdown_content,
        mimetype='text/markdown',
        headers={
            'Content-Disposition': f'attachment; filename=sentinel_report_{scan_id}.md'
        }
    )

@app.route('/api/code/report/pdf/<int:scan_id>', methods=['GET'])
def get_pdf_report(scan_id):
    """Generate and return PDF report for a scan"""
    scan = db.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    pdf_buffer = report_generator.generate_pdf(scan['result'])
    
    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'sentinel_report_{scan_id}.pdf'
    )

@app.route('/api/code/report/comparison/<int:old_id>/<int:new_id>', methods=['GET'])
def get_comparison_report(old_id, new_id):
    """Generate comparison report between two scans"""
    comparison = db.compare_scans(old_id, new_id)
    if 'error' in comparison:
        return jsonify(comparison), 404
    
    markdown_content = report_generator.generate_comparison_markdown(comparison)
    
    return Response(
        markdown_content,
        mimetype='text/markdown',
        headers={
            'Content-Disposition': f'attachment; filename=comparison_{old_id}_vs_{new_id}.md'
        }
    )

# =============================================================================
# WEBHOOKS
# =============================================================================

@app.route('/api/code/webhooks', methods=['GET'])
def list_webhooks():
    """List all webhooks"""
    active_only = request.args.get('active_only', 'true').lower() == 'true'
    webhooks = webhook_service.list_webhooks(active_only)
    return jsonify({"webhooks": webhooks})

@app.route('/api/code/webhooks', methods=['POST'])
def create_webhook():
    """
    Create a new webhook.
    
    Request Body:
        {
            "name": "My CI Webhook",
            "url": "https://example.com/webhook",
            "secret": "optional-secret",
            "events": ["scan_complete", "critical_found"],
            "repo_filter": "optional-repo-substring"
        }
    """
    try:
        data = request.get_json()
        
        if not data.get('name') or not data.get('url'):
            return jsonify({"error": "name and url are required"}), 400
        
        result = webhook_service.create_webhook(
            name=data['name'],
            url=data['url'],
            secret=data.get('secret'),
            events=data.get('events'),
            repo_filter=data.get('repo_filter')
        )
        
        if 'error' in result:
            return jsonify(result), 400
        
        return jsonify(result), 201
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/code/webhooks/<int:webhook_id>', methods=['GET'])
def get_webhook(webhook_id):
    """Get webhook by ID"""
    webhook = webhook_service.get_webhook(webhook_id)
    if not webhook:
        return jsonify({"error": "Webhook not found"}), 404
    return jsonify(webhook)

@app.route('/api/code/webhooks/<int:webhook_id>', methods=['PUT'])
def update_webhook(webhook_id):
    """Update webhook"""
    data = request.get_json()
    result = webhook_service.update_webhook(webhook_id, **data)
    return jsonify(result)

@app.route('/api/code/webhooks/<int:webhook_id>', methods=['DELETE'])
def delete_webhook(webhook_id):
    """Delete webhook"""
    result = webhook_service.delete_webhook(webhook_id)
    return jsonify(result)

@app.route('/api/code/webhooks/<int:webhook_id>/test', methods=['POST'])
def test_webhook(webhook_id):
    """Send test ping to webhook"""
    result = webhook_service.test_webhook(webhook_id)
    return jsonify(result)

@app.route('/api/code/webhooks/<int:webhook_id>/logs', methods=['GET'])
def get_webhook_logs(webhook_id):
    """Get webhook trigger logs"""
    limit = int(request.args.get('limit', 50))
    logs = webhook_service.get_webhook_logs(webhook_id, limit)
    return jsonify({"logs": logs})

# =============================================================================
# VULNERABILITY INFO
# =============================================================================

@app.route('/api/code/vulnerabilities', methods=['GET'])
def list_vulnerabilities():
    """List all vulnerability types that Sentinel Code can detect."""
    try:
        from solana_patterns import (
            CRITICAL_VULNERABILITIES,
            WARNING_VULNERABILITIES,
            IMPROVEMENT_SUGGESTIONS
        )
        from solana_defi_patterns import DEFI_VULNERABILITIES
        
        solana_vulns = {
            "critical": [
                {"id": v["id"], "title": v["title"], "severity": v["severity"], "description": v["description"]}
                for v in CRITICAL_VULNERABILITIES.values()
            ],
            "warnings": [
                {"id": v["id"], "title": v["title"], "severity": v["severity"], "description": v["description"]}
                for v in WARNING_VULNERABILITIES.values()
            ],
            "improvements": [
                {"id": v["id"], "title": v["title"], "severity": v["severity"], "description": v["description"]}
                for v in IMPROVEMENT_SUGGESTIONS.values()
            ]
        }
        
        defi_vulns = [
            {"id": v["id"], "title": v["title"], "severity": v["severity"], 
             "category": v["category"], "description": v["description"]}
            for v in DEFI_VULNERABILITIES.values()
        ]
        
        return jsonify({
            "solana": solana_vulns,
            "defi": defi_vulns,
            "general": {
                "critical": ["SQL Injection", "XSS", "Command Injection", "Hardcoded Credentials", 
                            "Authentication Bypass", "Insecure Deserialization", "Path Traversal"],
                "warnings": ["Missing Input Validation", "Weak Cryptography", "Information Disclosure",
                            "Missing Error Handling", "Insecure Configuration"],
                "improvements": ["Missing Type Hints", "Missing Documentation", "Code Duplication"]
            }
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# MAIN
# =============================================================================

# =============================================================================
# =============================================================================
# RATE LIMIT STATUS
# =============================================================================

@app.route('/api/code/rate-limit', methods=['GET'])
def get_rate_limit_status():
    """
    Get current rate limit status for the requesting IP.
    
    Response:
        {
            "ip": "x.x.x.x",
            "used": 2,
            "remaining": 1,
            "limit": 3,
            "reset_in_seconds": 3600,
            "window_hours": 24,
            "x402_info": "Add X-PAYMENT header after free tier exhausted"
        }
    """
    client_ip = get_client_ip(request)
    usage = rate_limiter.get_usage(client_ip)
    usage["ip"] = client_ip
    usage["x402_alternative"] = {
        "endpoint": "/api/code/analyze",
        "price": "$0.01 USDC",
        "network": "solana-mainnet",
        "benefit": "After free tier, add X-PAYMENT header for unlimited scans"
    }
    return jsonify(usage)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8100))
    debug = os.getenv('DEBUG', 'false').lower() == 'true'

    print(f"""
╔════════════════════════════════════════════════════════════════╗
║            SENTINEL CODE - Security Analysis API v2.1          ║
╠════════════════════════════════════════════════════════════════╣
║  Port: {port}                                                    ║
║                                                                ║
║  Core Features:                                                ║
║  • General code security analysis                              ║
║  • Solana/Anchor vulnerability detection (15+ checks)          ║
║  • DeFi protocol analysis (14+ additional checks)              ║
║  • Smart file sampling & prioritization                        ║
║                                                                ║
║  New in v2.1:                                                  ║
║  • Result caching (24h default TTL)                            ║
║  • Scan history & comparison                                   ║
║  • PDF & Markdown report generation                            ║
║  • Webhook notifications for CI/CD                             ║
║                                                                ║
║  Endpoints:                                                    ║
║  • POST /api/code/analyze         Full AI analysis             ║
║  • POST /api/code/scan            Quick scan (no AI)           ║
║  • GET  /api/code/history         Scan history                 ║
║  • GET  /api/code/compare         Compare scans                ║
║  • GET  /api/code/report/pdf/:id  PDF report                   ║
║  • GET  /api/code/report/markdown/:id  Markdown report         ║
║  • POST /api/code/webhooks        Create webhook               ║
║  • GET  /api/code/vulnerabilities List detectable vulns        ║
║  • GET  /api/code/health          Health check                 ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
