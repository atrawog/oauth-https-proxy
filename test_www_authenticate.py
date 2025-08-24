#!/usr/bin/env python3
"""Test WWW-Authenticate header compliance with RFC 9728 Section 5.1"""

import requests
import json

def test_www_authenticate_header():
    """Test that 401 responses include RFC 9728 compliant WWW-Authenticate header"""
    print("=" * 60)
    print("Testing WWW-Authenticate Header (RFC 9728 Section 5.1)")
    print("=" * 60)
    
    # Test 1: MCP endpoint with JSON content type (should get 401 with header)
    print("\n1. Testing MCP endpoint with JSON request:")
    response = requests.post(
        "https://claude.atratest.org/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
            "id": 1
        },
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        allow_redirects=False,
        verify=False
    )
    
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 401:
        print(f"   ✅ Returns 401 Unauthorized (correct for API request)")
        
        # Check WWW-Authenticate header
        www_auth = response.headers.get("WWW-Authenticate", "")
        if www_auth:
            print(f"   ✅ Has WWW-Authenticate header")
            print(f"   Header value: {www_auth}")
            
            # Parse and validate the header
            if "Bearer" in www_auth:
                print(f"   ✅ Uses Bearer scheme")
            if "realm=" in www_auth:
                print(f"   ✅ Has realm parameter")
            if "as_uri=" in www_auth:
                print(f"   ✅ Has as_uri (authorization server metadata)")
                # Extract as_uri
                if "as_uri=\"" in www_auth:
                    as_uri_start = www_auth.index("as_uri=\"") + 8
                    as_uri_end = www_auth.index("\"", as_uri_start)
                    as_uri = www_auth[as_uri_start:as_uri_end]
                    print(f"      Authorization server: {as_uri}")
            if "resource_uri=" in www_auth:
                print(f"   ✅ Has resource_uri (protected resource metadata)")
                # Extract resource_uri
                if "resource_uri=\"" in www_auth:
                    res_uri_start = www_auth.index("resource_uri=\"") + 14
                    res_uri_end = www_auth.index("\"", res_uri_start)
                    resource_uri = www_auth[res_uri_start:res_uri_end]
                    print(f"      Resource metadata: {resource_uri}")
        else:
            print(f"   ❌ Missing WWW-Authenticate header")
            return False
    elif response.status_code == 302:
        print(f"   ⚠️  Got redirect instead of 401 (may need to restart server)")
        location = response.headers.get("location", "")
        print(f"   Location: {location[:100]}...")
        return False
    else:
        print(f"   ❌ Unexpected status: {response.status_code}")
        return False
    
    # Test 2: Test with invalid bearer token (should also get 401 with header)
    print("\n2. Testing with invalid bearer token:")
    response = requests.post(
        "https://claude.atratest.org/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
            "id": 1
        },
        headers={
            "Authorization": "Bearer invalid_token_12345",
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        allow_redirects=False,
        verify=False
    )
    
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 401:
        print(f"   ✅ Returns 401 for invalid token")
        www_auth = response.headers.get("WWW-Authenticate", "")
        if www_auth:
            print(f"   ✅ Has WWW-Authenticate header")
            if "error=" in www_auth:
                print(f"   ✅ May include error parameter")
        else:
            print(f"   ⚠️  Missing WWW-Authenticate header")
    elif response.status_code == 302:
        print(f"   ⚠️  Got redirect (server may need restart)")
    
    # Test 3: Browser request (should redirect, not 401)
    print("\n3. Testing browser request (should redirect):")
    response = requests.get(
        "https://claude.atratest.org/mcp",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        allow_redirects=False,
        verify=False
    )
    
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 302:
        print(f"   ✅ Correctly redirects browser requests")
        location = response.headers.get("location", "")
        if "authorize" in location:
            print(f"   ✅ Redirects to OAuth authorize endpoint")
    elif response.status_code == 401:
        print(f"   ⚠️  Browser request got 401 (should redirect)")
    
    return True

def test_metadata_endpoints():
    """Test that metadata endpoints referenced in WWW-Authenticate are accessible"""
    print("\n4. Testing metadata endpoints referenced in WWW-Authenticate:")
    
    # Check authorization server metadata
    as_url = "https://auth.atratest.org/.well-known/oauth-authorization-server"
    response = requests.get(as_url, verify=False)
    print(f"   Authorization server metadata: {response.status_code}")
    if response.status_code == 200:
        print(f"   ✅ {as_url}")
    
    # Check protected resource metadata
    res_url = "https://claude.atratest.org/.well-known/oauth-protected-resource"
    response = requests.get(res_url, verify=False)
    print(f"   Protected resource metadata: {response.status_code}")
    if response.status_code == 200:
        print(f"   ✅ {res_url}")
    
    return True

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    test_www_authenticate_header()
    test_metadata_endpoints()
    
    print("\n" + "=" * 60)
    print("RFC 9728 Section 5.1 Compliance Summary:")
    print("- WWW-Authenticate header MUST be included in 401 responses")
    print("- Header MUST include as_uri (authorization server metadata)")
    print("- Header MUST include resource_uri (protected resource metadata)")
    print("- Both metadata endpoints MUST be accessible")
    print("\nNote: Server restart may be needed for changes to take effect")
    print("=" * 60)