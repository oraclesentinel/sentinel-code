"""
x402 Payment Handler for Sentinel Code
Integrates PayAI x402 micropayments for unlimited scans after free tier exhausted
"""

import os
from flask import Flask, request

from x402.http import FacilitatorConfig, HTTPFacilitatorClientSync, PaymentOption
from x402.http.middleware.flask import payment_middleware
from x402.http.types import RouteConfig
from x402.mechanisms.svm.exact import ExactSvmServerScheme
from x402.server import x402ResourceServerSync

# =============================================================================
# CONFIGURATION
# =============================================================================

# Solana Mainnet
SVM_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

# Oracle Sentinel wallet to receive USDC payments
SVM_ADDRESS = os.getenv("X402_SVM_ADDRESS", "FHoDf2HHcKxs7WkVGiYzxSVscDLHbfhGzUqDLw7qqdCt")

# PayAI Facilitator
FACILITATOR_URL = os.getenv("X402_FACILITATOR_URL", "https://facilitator.payai.network")

# Price per scan
SCAN_PRICE = os.getenv("X402_SCAN_PRICE", "$0.01")

# =============================================================================
# x402 SETUP
# =============================================================================

# Global x402 server instance
_x402_server = None
_x402_facilitator = None

def init_x402():
    """Initialize x402 server (called once at startup)."""
    global _x402_server, _x402_facilitator
    
    print(f"[x402] Initializing PayAI x402...")
    print(f"[x402] Network: {SVM_NETWORK}")
    print(f"[x402] Wallet: {SVM_ADDRESS}")
    print(f"[x402] Facilitator: {FACILITATOR_URL}")
    print(f"[x402] Price per scan: {SCAN_PRICE}")
    
    # Create facilitator client
    _x402_facilitator = HTTPFacilitatorClientSync(
        FacilitatorConfig(url=FACILITATOR_URL)
    )
    
    # Create x402 server
    _x402_server = x402ResourceServerSync(_x402_facilitator)
    
    # Register Solana payment scheme
    _x402_server.register(SVM_NETWORK, ExactSvmServerScheme())
    
    print(f"[x402] Initialized successfully")

def get_payment_requirements():
    """Get payment requirements for x402 response."""
    return {
        "x402Version": 2,
        "error": "Free tier exhausted. Payment required for additional scans.",
        "resource": {
            "url": request.url,
            "description": "Security scan - pay $0.01 USDC for unlimited access",
            "mimeType": "application/json"
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": SVM_NETWORK,
                "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # USDC
                "amount": "10000",  # $0.01 (6 decimals)
                "payTo": SVM_ADDRESS,
                "maxTimeoutSeconds": 300,
                "extra": {
                    "feePayer": "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"  # PayAI fee payer
                }
            }
        ]
    }

def verify_and_settle_payment(payment_header: str) -> dict:
    """
    Verify and settle x402 payment.
    
    Args:
        payment_header: Base64 encoded payment from X-PAYMENT header
        
    Returns:
        dict with 'success' and 'payer' or 'error'
    """
    global _x402_server
    
    if not _x402_server:
        return {"success": False, "error": "x402 not initialized"}
    
    try:
        import base64
        import json
        
        # Decode payment payload
        payment_data = json.loads(base64.b64decode(payment_header))
        
        # Build payment requirements for verification
        payment_requirements = {
            "scheme": "exact",
            "network": SVM_NETWORK,
            "amount": "10000",
            "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "payTo": SVM_ADDRESS,
            "maxTimeoutSeconds": 300
        }
        
        # Verify payment
        verify_result = _x402_server.verify(payment_data, payment_requirements)
        
        if not verify_result.get("isValid"):
            return {
                "success": False, 
                "error": verify_result.get("invalidReason", "Payment verification failed")
            }
        
        # Settle payment
        settle_result = _x402_server.settle(payment_data, payment_requirements)
        
        if not settle_result.get("success"):
            return {
                "success": False,
                "error": settle_result.get("errorReason", "Payment settlement failed")
            }
        
        return {
            "success": True,
            "payer": settle_result.get("payer"),
            "transaction": settle_result.get("transaction")
        }
        
    except Exception as e:
        print(f"[x402] Payment error: {e}")
        return {"success": False, "error": str(e)}

def get_x402_info() -> dict:
    """Return x402 configuration info for health check."""
    return {
        "enabled": True,
        "network": SVM_NETWORK,
        "wallet": SVM_ADDRESS,
        "facilitator": FACILITATOR_URL,
        "price_per_scan": SCAN_PRICE,
        "description": "Free tier: 3 scans/day. After that, pay $0.01 USDC per scan."
    }
