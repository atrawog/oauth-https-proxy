#!/usr/bin/env python3
"""Test all FastAPI endpoints for proper authentication."""

import os
import sys
import json
import httpx
from typing import Dict, List, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.test_utils import get_admin_token

# Test configuration
# Use the GUI proxy which provides access to the API
API_URL = "https://gui.atradev.org"
ADMIN_TOKEN = get_admin_token()


def test_endpoint(method: str, path: str, auth_required: bool, description: str) -> Tuple[bool, str]:
    """Test a single endpoint for authentication.
    
    Returns:
        Tuple of (passed, details)
    """
    client = httpx.Client(verify=False)  # Skip SSL verification for test domains
    
    # First test WITHOUT authentication
    try:
        if method == "GET":
            response = client.get(f"{API_URL}{path}")
        elif method == "POST":
            response = client.post(f"{API_URL}{path}", json={})
        elif method == "PUT":
            response = client.put(f"{API_URL}{path}", json={})
        elif method == "DELETE":
            response = client.delete(f"{API_URL}{path}")
        else:
            return False, f"Unknown method: {method}"
        
        if auth_required:
            # Should get 401 or 403 without auth
            if response.status_code in [401, 403]:
                # Now test WITH authentication
                headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
                if method == "GET":
                    auth_response = client.get(f"{API_URL}{path}", headers=headers)
                elif method == "POST":
                    auth_response = client.post(f"{API_URL}{path}", json={}, headers=headers)
                elif method == "PUT":
                    auth_response = client.put(f"{API_URL}{path}", json={}, headers=headers)
                elif method == "DELETE":
                    auth_response = client.delete(f"{API_URL}{path}", headers=headers)
                
                # Should not get 401/403 with valid auth (might get 404, 422, etc)
                if auth_response.status_code not in [401, 403]:
                    return True, "Properly secured"
                else:
                    return False, f"Still unauthorized with token: {auth_response.status_code}"
            else:
                return False, f"No auth required but expected: {response.status_code}"
        else:
            # Should be accessible without auth
            if response.status_code not in [401, 403]:
                return True, "Publicly accessible as expected"
            else:
                return False, f"Requires auth but shouldn't: {response.status_code}"
                
    except Exception as e:
        return False, f"Error: {str(e)}"
    finally:
        client.close()


def main():
    """Test all endpoints for proper authentication."""
    
    # Get the actual ADMIN token from environment
    admin_token = ADMIN_TOKEN
    if not admin_token:
        # Try to get from environment as fallback
        import subprocess
        result = subprocess.run("grep ADMIN_TOKEN .env | cut -d= -f2", shell=True, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            admin_token = result.stdout.strip()
            global ADMIN_TOKEN
            ADMIN_TOKEN = admin_token
    
    print(f"Using admin token: {ADMIN_TOKEN[:20]}..." if ADMIN_TOKEN else "NO ADMIN TOKEN FOUND!")
    
    # Define all endpoints and their expected auth requirements
    endpoints = [
        # Format: (method, path, auth_required, description)
        
        # Root and static
        ("GET", "/", False, "Root endpoint (serves GUI or proxy)"),
        ("GET", "/static/test.js", False, "Static files (public from localhost)"),
        
        # Health and ACME
        ("GET", "/health", False, "Health check (auth for remote)"),
        ("GET", "/.well-known/acme-challenge/test", False, "ACME challenge (must be public)"),
        
        # Certificate endpoints
        ("POST", "/certificates", True, "Create certificate"),
        ("POST", "/certificates/multi-domain", True, "Create multi-domain certificate"),
        ("GET", "/certificates", True, "List certificates"),
        ("GET", "/certificates/test-cert", True, "Get certificate"),
        ("GET", "/certificates/test-cert/status", True, "Get certificate status"),
        ("POST", "/certificates/test-cert/renew", True, "Renew certificate"),
        ("POST", "/certificates/test-cert/convert-to-production", True, "Convert certificate"),
        ("DELETE", "/certificates/test-cert/domains/example.com", True, "Delete domain"),
        
        # Token endpoints
        ("PUT", "/token/email", True, "Update token email"),
        ("GET", "/token/info", True, "Get token info"),
        
        # Proxy endpoints
        ("POST", "/proxy/targets", True, "Create proxy target"),
        ("GET", "/proxy/targets", True, "List proxy targets"),
        ("GET", "/proxy/targets/test.example.com", True, "Get proxy target"),
        ("PUT", "/proxy/targets/test.example.com", True, "Update proxy target"),
        ("DELETE", "/proxy/targets/test.example.com", True, "Delete proxy target"),
        
        # Proxy auth endpoints
        ("POST", "/proxy/targets/test.example.com/auth", True, "Configure proxy auth"),
        ("DELETE", "/proxy/targets/test.example.com/auth", True, "Remove proxy auth"),
        ("GET", "/proxy/targets/test.example.com/auth", False, "Get proxy auth (optional auth)"),
        
        # Proxy route endpoints
        ("GET", "/proxy/targets/test.example.com/routes", False, "Get proxy routes (optional auth)"),
        ("PUT", "/proxy/targets/test.example.com/routes", True, "Update proxy routes"),
        ("POST", "/proxy/targets/test.example.com/routes/test-route/enable", True, "Enable route"),
        ("POST", "/proxy/targets/test.example.com/routes/test-route/disable", True, "Disable route"),
        
        # Route endpoints
        ("POST", "/routes", True, "Create route"),
        ("GET", "/routes", True, "List routes"),
        ("GET", "/routes/test-route", True, "Get route"),
        ("PUT", "/routes/test-route", True, "Update route"),
        ("DELETE", "/routes/test-route", True, "Delete route"),
        
        # Resource endpoints (MCP)
        ("POST", "/resources", True, "Create resource"),
        ("GET", "/resources", True, "List resources"),
        ("GET", "/resources/test.example.com", True, "Get resource"),
        ("PUT", "/resources/test.example.com", True, "Update resource"),
        ("DELETE", "/resources/test.example.com", True, "Delete resource"),
        ("POST", "/resources/auto-register", True, "Auto-register resources"),
        ("POST", "/resources/test.example.com/validate-token", True, "Validate token"),
        
        # OAuth status endpoints (intentionally public for monitoring)
        ("GET", "/oauth-status/clients", False, "List OAuth clients (monitoring)"),
        ("GET", "/oauth-status/clients/test-client", False, "Get OAuth client (monitoring)"),
        ("GET", "/oauth-status/tokens", False, "Token statistics (monitoring)"),
        ("GET", "/oauth-status/sessions", False, "List sessions (monitoring)"),
        ("DELETE", "/oauth-status/sessions/test-session", True, "Revoke session (requires auth)"),
        ("GET", "/oauth-status/metrics", False, "OAuth metrics (monitoring)"),
        ("GET", "/oauth-status/health", False, "OAuth health (monitoring)"),
        ("GET", "/oauth-status/proxies", False, "Proxy OAuth status (monitoring)"),
    ]
    
    print("🔒 Testing Endpoint Security")
    print("=" * 80)
    print(f"Base URL: {API_URL}")
    print(f"Total endpoints to test: {len(endpoints)}")
    print("=" * 80)
    print()
    
    passed = 0
    failed = 0
    results = []
    
    for method, path, auth_required, description in endpoints:
        success, details = test_endpoint(method, path, auth_required, description)
        
        status = "✅ PASS" if success else "❌ FAIL"
        auth_str = "Auth Required" if auth_required else "Public"
        
        print(f"{status} {method:6} {path:50} [{auth_str:13}] - {description}")
        if not success:
            print(f"         Details: {details}")
        
        results.append({
            "method": method,
            "path": path,
            "auth_required": auth_required,
            "description": description,
            "passed": success,
            "details": details
        })
        
        if success:
            passed += 1
        else:
            failed += 1
    
    # Summary
    print()
    print("=" * 80)
    print("📊 Security Test Summary")
    print("=" * 80)
    print(f"Total tests: {len(endpoints)}")
    print(f"Passed: {passed} ({passed/len(endpoints)*100:.1f}%)")
    print(f"Failed: {failed} ({failed/len(endpoints)*100:.1f}%)")
    
    if failed > 0:
        print()
        print("❌ Failed endpoints:")
        for r in results:
            if not r["passed"]:
                print(f"  - {r['method']} {r['path']}: {r['details']}")
    
    if failed == 0:
        print()
        print("🎉 All endpoints have proper authentication! 🎉")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())