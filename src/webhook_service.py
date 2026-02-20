"""
Webhook Service - CI/CD Integration for Sentinel Code
Sends notifications on scan events
"""

import os
import json
import hmac
import hashlib
import requests
from datetime import datetime
from typing import Dict, List, Optional
from database import db


class WebhookService:
    """
    Webhook service for CI/CD integration.
    
    Features:
    - Send notifications on scan_complete, critical_found, score_changed
    - HMAC signature for security
    - Retry logic
    - Event filtering by repo
    """
    
    EVENTS = [
        'scan_complete',      # Triggered after every scan
        'critical_found',     # Triggered when critical issues found
        'score_improved',     # Triggered when score increases
        'score_decreased',    # Triggered when score decreases
    ]
    
    def __init__(self):
        self.timeout = 10  # seconds
        self.max_retries = 3
    
    # =========================================================================
    # WEBHOOK MANAGEMENT
    # =========================================================================
    
    def create_webhook(self, name: str, url: str, secret: str = None,
                       events: List[str] = None, repo_filter: str = None) -> Dict:
        """
        Create a new webhook.
        
        Args:
            name: Human-readable name
            url: Webhook endpoint URL
            secret: Optional secret for HMAC signing
            events: List of events to trigger on (default: scan_complete)
            repo_filter: Optional repo URL substring filter
        """
        if events:
            # Validate events
            invalid = [e for e in events if e not in self.EVENTS]
            if invalid:
                return {'error': f'Invalid events: {invalid}', 'valid_events': self.EVENTS}
            events_str = ','.join(events)
        else:
            events_str = 'scan_complete'
        
        webhook_id = db.create_webhook(
            name=name,
            url=url,
            secret=secret,
            events=events_str,
            repo_filter=repo_filter
        )
        
        return {
            'id': webhook_id,
            'name': name,
            'url': url,
            'events': events_str.split(','),
            'repo_filter': repo_filter,
            'created': True
        }
    
    def list_webhooks(self, active_only: bool = True) -> List[Dict]:
        """List all webhooks"""
        webhooks = db.get_webhooks(active_only=active_only)
        for wh in webhooks:
            wh['events'] = wh['events'].split(',') if wh['events'] else []
        return webhooks
    
    def get_webhook(self, webhook_id: int) -> Optional[Dict]:
        """Get webhook by ID"""
        webhook = db.get_webhook_by_id(webhook_id)
        if webhook:
            webhook['events'] = webhook['events'].split(',') if webhook['events'] else []
        return webhook
    
    def update_webhook(self, webhook_id: int, **kwargs) -> Dict:
        """Update webhook"""
        if 'events' in kwargs and isinstance(kwargs['events'], list):
            kwargs['events'] = ','.join(kwargs['events'])
        
        success = db.update_webhook(webhook_id, **kwargs)
        return {'updated': success}
    
    def delete_webhook(self, webhook_id: int) -> Dict:
        """Delete webhook"""
        success = db.delete_webhook(webhook_id)
        return {'deleted': success}
    
    def get_webhook_logs(self, webhook_id: int, limit: int = 50) -> List[Dict]:
        """Get webhook trigger logs"""
        return db.get_webhook_logs(webhook_id, limit)
    
    # =========================================================================
    # TRIGGER WEBHOOKS
    # =========================================================================
    
    def trigger_scan_complete(self, scan_result: Dict, scan_id: int = None):
        """
        Trigger webhooks for scan_complete event.
        Also triggers critical_found if applicable.
        """
        repo_url = scan_result.get('repo', '')
        
        # Prepare payload
        payload = self._build_payload('scan_complete', scan_result, scan_id)
        
        # Get matching webhooks
        webhooks = db.get_webhooks_for_event('scan_complete', repo_url)
        
        # Send to each webhook
        for webhook in webhooks:
            self._send_webhook(webhook, 'scan_complete', payload)
        
        # Also trigger critical_found if there are critical issues
        critical_count = len(scan_result.get('critical', []))
        if critical_count > 0:
            self.trigger_critical_found(scan_result, scan_id)
    
    def trigger_critical_found(self, scan_result: Dict, scan_id: int = None):
        """Trigger webhooks for critical_found event"""
        repo_url = scan_result.get('repo', '')
        
        payload = self._build_payload('critical_found', scan_result, scan_id)
        payload['critical_count'] = len(scan_result.get('critical', []))
        payload['critical_issues'] = [
            {
                'id': issue.get('id'),
                'title': issue.get('title'),
                'file': issue.get('file'),
                'line': issue.get('line')
            }
            for issue in scan_result.get('critical', [])[:10]  # Limit to 10
        ]
        
        webhooks = db.get_webhooks_for_event('critical_found', repo_url)
        
        for webhook in webhooks:
            self._send_webhook(webhook, 'critical_found', payload)
    
    def trigger_score_changed(self, repo_url: str, old_score: int, new_score: int, 
                              scan_id: int = None):
        """Trigger webhooks for score change events"""
        
        if new_score > old_score:
            event = 'score_improved'
        elif new_score < old_score:
            event = 'score_decreased'
        else:
            return  # No change
        
        payload = {
            'event': event,
            'repo': repo_url,
            'scan_id': scan_id,
            'old_score': old_score,
            'new_score': new_score,
            'score_change': new_score - old_score,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        webhooks = db.get_webhooks_for_event(event, repo_url)
        
        for webhook in webhooks:
            self._send_webhook(webhook, event, payload)
    
    # =========================================================================
    # INTERNAL METHODS
    # =========================================================================
    
    def _build_payload(self, event: str, scan_result: Dict, scan_id: int = None) -> Dict:
        """Build webhook payload"""
        return {
            'event': event,
            'scan_id': scan_id,
            'repo': scan_result.get('repo'),
            'is_solana_project': scan_result.get('is_solana_project', False),
            'framework': scan_result.get('framework'),
            'score': scan_result.get('score', 0),
            'summary': {
                'critical_count': len(scan_result.get('critical', [])),
                'warning_count': len(scan_result.get('warnings', [])),
                'improvement_count': len(scan_result.get('improvements', [])),
                'files_analyzed': scan_result.get('files_analyzed', 0),
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def _sign_payload(self, payload: str, secret: str) -> str:
        """Generate HMAC-SHA256 signature"""
        return hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def _send_webhook(self, webhook: Dict, event: str, payload: Dict) -> bool:
        """Send webhook with retry logic"""
        
        url = webhook['url']
        secret = webhook.get('secret')
        webhook_id = webhook['id']
        
        payload_str = json.dumps(payload, separators=(',', ':'))
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'SentinelCode-Webhook/2.0',
            'X-Sentinel-Event': event,
            'X-Sentinel-Delivery': str(datetime.utcnow().timestamp())
        }
        
        # Add signature if secret is configured
        if secret:
            signature = self._sign_payload(payload_str, secret)
            headers['X-Sentinel-Signature'] = f'sha256={signature}'
        
        # Try with retries
        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    url,
                    data=payload_str,
                    headers=headers,
                    timeout=self.timeout
                )
                
                success = 200 <= response.status_code < 300
                
                # Log the attempt
                db.log_webhook_trigger(
                    webhook_id=webhook_id,
                    event=event,
                    payload=payload,
                    response_code=response.status_code,
                    response_body=response.text[:1000],
                    success=success
                )
                
                if success:
                    print(f"[Webhook] Sent {event} to {webhook['name']} (ID: {webhook_id})")
                    return True
                else:
                    print(f"[Webhook] Failed {event} to {webhook['name']}: {response.status_code}")
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    
            except requests.Timeout:
                last_error = "Request timeout"
                print(f"[Webhook] Timeout sending {event} to {webhook['name']}")
            except requests.RequestException as e:
                last_error = str(e)
                print(f"[Webhook] Error sending {event} to {webhook['name']}: {e}")
        
        # Log final failure
        db.log_webhook_trigger(
            webhook_id=webhook_id,
            event=event,
            payload=payload,
            response_code=0,
            response_body=last_error or "Unknown error",
            success=False
        )
        
        return False
    
    def test_webhook(self, webhook_id: int) -> Dict:
        """Send a test ping to webhook"""
        webhook = self.get_webhook(webhook_id)
        if not webhook:
            return {'error': 'Webhook not found'}
        
        payload = {
            'event': 'test',
            'message': 'This is a test webhook from Sentinel Code',
            'webhook_id': webhook_id,
            'webhook_name': webhook['name'],
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        success = self._send_webhook(webhook, 'test', payload)
        
        return {
            'success': success,
            'webhook_id': webhook_id,
            'webhook_name': webhook['name'],
            'url': webhook['url']
        }


# Singleton instance
webhook_service = WebhookService()
