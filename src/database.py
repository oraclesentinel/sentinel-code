"""
Database Module - SQLite storage for Sentinel Code
Handles: Caching, Scan History, Webhooks, Comparisons
"""

import os
import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'sentinel_code.db')


class Database:
    """
    SQLite database for Sentinel Code.
    
    Features:
    - Scan result caching (configurable TTL)
    - Scan history tracking
    - Webhook management
    - Scan comparison
    """
    
    def __init__(self):
        self.db_path = DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
    
    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection with row factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        """Initialize database tables"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # Scan cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_url TEXT NOT NULL,
                repo_hash TEXT NOT NULL UNIQUE,
                result JSON NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                hit_count INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_hash ON scan_cache(repo_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cache_expires ON scan_cache(expires_at)')
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_url TEXT NOT NULL,
                repo_hash TEXT NOT NULL,
                is_solana_project BOOLEAN,
                framework TEXT,
                score INTEGER,
                critical_count INTEGER,
                warning_count INTEGER,
                improvement_count INTEGER,
                files_analyzed INTEGER,
                total_lines INTEGER,
                result JSON NOT NULL,
                scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_history_repo ON scan_history(repo_url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_history_time ON scan_history(scanned_at DESC)')
        
        # Webhooks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webhooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                secret TEXT,
                events TEXT NOT NULL DEFAULT 'scan_complete',
                repo_filter TEXT,
                active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_triggered DATETIME,
                trigger_count INTEGER DEFAULT 0,
                last_error TEXT
            )
        ''')
        
        # Webhook logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webhook_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                webhook_id INTEGER NOT NULL,
                event TEXT NOT NULL,
                payload JSON,
                response_code INTEGER,
                response_body TEXT,
                success BOOLEAN,
                triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    # =========================================================================
    # CACHE METHODS
    # =========================================================================
    
    def _get_repo_hash(self, repo_url: str) -> str:
        """Generate hash for repo URL"""
        return hashlib.sha256(repo_url.lower().strip().encode()).hexdigest()[:16]
    
    def get_cached_scan(self, repo_url: str) -> Optional[Dict]:
        """
        Get cached scan result if not expired.
        Returns None if not found or expired.
        """
        repo_hash = self._get_repo_hash(repo_url)
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, result, created_at, expires_at 
            FROM scan_cache 
            WHERE repo_hash = ? AND expires_at > datetime('now')
        ''', (repo_hash,))
        
        row = cursor.fetchone()
        if row:
            # Update hit count
            cursor.execute(
                'UPDATE scan_cache SET hit_count = hit_count + 1 WHERE id = ?',
                (row['id'],)
            )
            conn.commit()
            conn.close()
            
            result = json.loads(row['result'])
            result['_cache'] = {
                'cached': True,
                'cached_at': row['created_at'],
                'expires_at': row['expires_at']
            }
            return result
        
        conn.close()
        return None
    
    def cache_scan(self, repo_url: str, result: Dict, ttl_hours: int = 24):
        """
        Cache scan result with TTL.
        Default TTL: 24 hours
        """
        repo_hash = self._get_repo_hash(repo_url)
        expires_at = datetime.now() + timedelta(hours=ttl_hours)
        
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # Upsert cache entry
        cursor.execute('''
            INSERT INTO scan_cache (repo_url, repo_hash, result, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(repo_hash) DO UPDATE SET
                result = excluded.result,
                created_at = CURRENT_TIMESTAMP,
                expires_at = excluded.expires_at,
                hit_count = 0
        ''', (repo_url, repo_hash, json.dumps(result), expires_at.isoformat()))
        
        conn.commit()
        conn.close()
    
    def invalidate_cache(self, repo_url: str) -> bool:
        """Invalidate cache for a specific repo"""
        repo_hash = self._get_repo_hash(repo_url)
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM scan_cache WHERE repo_hash = ?', (repo_hash,))
        deleted = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return deleted
    
    def cleanup_expired_cache(self) -> int:
        """Remove all expired cache entries"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM scan_cache WHERE expires_at < datetime('now')")
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        return deleted
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_entries,
                SUM(hit_count) as total_hits,
                COUNT(CASE WHEN expires_at > datetime('now') THEN 1 END) as active_entries
            FROM scan_cache
        ''')
        row = cursor.fetchone()
        
        conn.close()
        return {
            'total_entries': row['total_entries'] or 0,
            'total_hits': row['total_hits'] or 0,
            'active_entries': row['active_entries'] or 0
        }
    
    # =========================================================================
    # HISTORY METHODS
    # =========================================================================
    
    def save_scan_history(self, repo_url: str, result: Dict):
        """Save scan to history"""
        repo_hash = self._get_repo_hash(repo_url)
        
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_history (
                repo_url, repo_hash, is_solana_project, framework,
                score, critical_count, warning_count, improvement_count,
                files_analyzed, total_lines, result
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            repo_url,
            repo_hash,
            result.get('is_solana_project', False),
            result.get('framework'),
            result.get('score', 0),
            len(result.get('critical', [])),
            len(result.get('warnings', [])),
            len(result.get('improvements', [])),
            result.get('files_analyzed', 0),
            result.get('total_lines', 0),
            json.dumps(result)
        ))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
    
    def get_scan_history(self, repo_url: str = None, limit: int = 20) -> List[Dict]:
        """Get scan history, optionally filtered by repo"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        if repo_url:
            cursor.execute('''
                SELECT id, repo_url, is_solana_project, framework, score,
                       critical_count, warning_count, improvement_count,
                       files_analyzed, total_lines, scanned_at
                FROM scan_history
                WHERE repo_url = ?
                ORDER BY scanned_at DESC
                LIMIT ?
            ''', (repo_url, limit))
        else:
            cursor.execute('''
                SELECT id, repo_url, is_solana_project, framework, score,
                       critical_count, warning_count, improvement_count,
                       files_analyzed, total_lines, scanned_at
                FROM scan_history
                ORDER BY scanned_at DESC
                LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_scan_by_id(self, scan_id: int) -> Optional[Dict]:
        """Get full scan result by ID"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scan_history WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        
        conn.close()
        
        if row:
            result = dict(row)
            result['result'] = json.loads(result['result'])
            return result
        return None
    
    def compare_scans(self, scan_id_old: int, scan_id_new: int) -> Dict:
        """
        Compare two scans and return differences.
        Shows: fixed issues, new issues, score change
        """
        old_scan = self.get_scan_by_id(scan_id_old)
        new_scan = self.get_scan_by_id(scan_id_new)
        
        if not old_scan or not new_scan:
            return {'error': 'Scan not found'}
        
        old_result = old_scan['result']
        new_result = new_scan['result']
        
        # Extract issue IDs/signatures
        def get_issue_signatures(issues: List[Dict]) -> set:
            signatures = set()
            for issue in issues:
                # Create signature from file + line + id
                sig = f"{issue.get('file', '')}:{issue.get('line', '')}:{issue.get('id', '')}"
                signatures.add(sig)
            return signatures
        
        old_critical = get_issue_signatures(old_result.get('critical', []))
        new_critical = get_issue_signatures(new_result.get('critical', []))
        
        old_warnings = get_issue_signatures(old_result.get('warnings', []))
        new_warnings = get_issue_signatures(new_result.get('warnings', []))
        
        # Calculate differences
        fixed_critical = old_critical - new_critical
        new_critical_issues = new_critical - old_critical
        
        fixed_warnings = old_warnings - new_warnings
        new_warning_issues = new_warnings - old_warnings
        
        score_change = (new_result.get('score', 0) or 0) - (old_result.get('score', 0) or 0)
        
        return {
            'old_scan': {
                'id': scan_id_old,
                'scanned_at': old_scan['scanned_at'],
                'score': old_result.get('score', 0),
                'critical_count': len(old_result.get('critical', [])),
                'warning_count': len(old_result.get('warnings', []))
            },
            'new_scan': {
                'id': scan_id_new,
                'scanned_at': new_scan['scanned_at'],
                'score': new_result.get('score', 0),
                'critical_count': len(new_result.get('critical', [])),
                'warning_count': len(new_result.get('warnings', []))
            },
            'comparison': {
                'score_change': score_change,
                'score_improved': score_change > 0,
                'fixed_critical': len(fixed_critical),
                'new_critical': len(new_critical_issues),
                'fixed_warnings': len(fixed_warnings),
                'new_warnings': len(new_warning_issues),
                'fixed_critical_list': list(fixed_critical),
                'new_critical_list': list(new_critical_issues),
                'fixed_warnings_list': list(fixed_warnings),
                'new_warnings_list': list(new_warning_issues)
            },
            'summary': self._generate_comparison_summary(
                score_change, 
                len(fixed_critical), 
                len(new_critical_issues),
                len(fixed_warnings),
                len(new_warning_issues)
            )
        }
    
    def _generate_comparison_summary(self, score_change: int, fixed_crit: int, 
                                      new_crit: int, fixed_warn: int, new_warn: int) -> str:
        """Generate human-readable comparison summary"""
        parts = []
        
        if score_change > 0:
            parts.append(f"Score improved by {score_change} points.")
        elif score_change < 0:
            parts.append(f"Score decreased by {abs(score_change)} points.")
        else:
            parts.append("Score unchanged.")
        
        if fixed_crit > 0:
            parts.append(f"{fixed_crit} critical issue(s) fixed.")
        if new_crit > 0:
            parts.append(f"{new_crit} new critical issue(s) introduced.")
        
        if fixed_warn > 0:
            parts.append(f"{fixed_warn} warning(s) resolved.")
        if new_warn > 0:
            parts.append(f"{new_warn} new warning(s) introduced.")
        
        if fixed_crit > 0 and new_crit == 0 and new_warn == 0:
            parts.append("Great progress!")
        elif new_crit > 0:
            parts.append("Attention needed on new critical issues.")
        
        return " ".join(parts)
    
    def get_repo_trend(self, repo_url: str, limit: int = 10) -> List[Dict]:
        """Get score trend for a repo over time"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, score, critical_count, warning_count, scanned_at
            FROM scan_history
            WHERE repo_url = ?
            ORDER BY scanned_at DESC
            LIMIT ?
        ''', (repo_url, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in reversed(rows)]  # Chronological order
    
    # =========================================================================
    # WEBHOOK METHODS
    # =========================================================================
    
    def create_webhook(self, name: str, url: str, secret: str = None,
                       events: str = 'scan_complete', repo_filter: str = None) -> int:
        """Create a new webhook"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO webhooks (name, url, secret, events, repo_filter)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, url, secret, events, repo_filter))
        
        webhook_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return webhook_id
    
    def get_webhooks(self, active_only: bool = True) -> List[Dict]:
        """Get all webhooks"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        if active_only:
            cursor.execute('SELECT * FROM webhooks WHERE active = 1')
        else:
            cursor.execute('SELECT * FROM webhooks')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_webhook_by_id(self, webhook_id: int) -> Optional[Dict]:
        """Get webhook by ID"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM webhooks WHERE id = ?', (webhook_id,))
        row = cursor.fetchone()
        
        conn.close()
        return dict(row) if row else None
    
    def update_webhook(self, webhook_id: int, **kwargs) -> bool:
        """Update webhook fields"""
        allowed_fields = ['name', 'url', 'secret', 'events', 'repo_filter', 'active']
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return False
        
        conn = self._get_conn()
        cursor = conn.cursor()
        
        set_clause = ', '.join(f'{k} = ?' for k in updates.keys())
        values = list(updates.values()) + [webhook_id]
        
        cursor.execute(f'UPDATE webhooks SET {set_clause} WHERE id = ?', values)
        updated = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return updated
    
    def delete_webhook(self, webhook_id: int) -> bool:
        """Delete a webhook"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM webhooks WHERE id = ?', (webhook_id,))
        deleted = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return deleted
    
    def log_webhook_trigger(self, webhook_id: int, event: str, payload: Dict,
                            response_code: int, response_body: str, success: bool):
        """Log webhook trigger attempt"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO webhook_logs (webhook_id, event, payload, response_code, response_body, success)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (webhook_id, event, json.dumps(payload), response_code, response_body, success))
        
        # Update webhook stats
        cursor.execute('''
            UPDATE webhooks 
            SET last_triggered = CURRENT_TIMESTAMP, 
                trigger_count = trigger_count + 1,
                last_error = CASE WHEN ? THEN NULL ELSE ? END
            WHERE id = ?
        ''', (success, response_body[:500] if not success else None, webhook_id))
        
        conn.commit()
        conn.close()
    
    def get_webhook_logs(self, webhook_id: int, limit: int = 50) -> List[Dict]:
        """Get webhook trigger logs"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM webhook_logs
            WHERE webhook_id = ?
            ORDER BY triggered_at DESC
            LIMIT ?
        ''', (webhook_id, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_webhooks_for_event(self, event: str, repo_url: str = None) -> List[Dict]:
        """Get active webhooks that match the event and optional repo filter"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM webhooks
            WHERE active = 1 AND events LIKE ?
        ''', (f'%{event}%',))
        
        rows = cursor.fetchall()
        conn.close()
        
        webhooks = []
        for row in rows:
            webhook = dict(row)
            # Check repo filter
            if webhook['repo_filter']:
                if repo_url and webhook['repo_filter'] not in repo_url:
                    continue
            webhooks.append(webhook)
        
        return webhooks


# Singleton instance
db = Database()
