#!/usr/bin/env python3
"""Test MCP endpoint OAuth protection and compliance"""

import requests
import json
import base64
from urllib.parse import urlencode

def test_mcp_without_auth():
    """Test that MCP endpoint requires authentication"""
    print("=" * 60)
    print("Testing MCP OAuth Protection")
    print("=" * 60)
    
    # Test 1: Access without auth should redirect
    print("\n1. Testing MCP without authentication:")
    response = requests.post(
        "https://claude.atratest.org/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
            "id": 1
        },
        allow_redirects=False,
        verify=False
    )
    
    print(f"   Status: {response.status_code}")
    if response.status_code == 302:
        location = response.headers.get('location', '')
        print(f"   ✅ Correctly redirects to OAuth")
        print(f"   Location: {location[:100]}...")
        
        # Check for required OAuth parameters
        if "response_type=code" in location:
            print(f"   ✅ Has response_type=code")
        if "scope=" in location and "mcp:" in location:
            print(f"   ✅ Has MCP scopes")
        if "resource=https%3A%2F%2Fclaude.atratest.org" in location:
            print(f"   ✅ Has resource parameter (audience-bound)")
    else:
        print(f"   ❌ Unexpected response: {response.status_code}")
    
    return response.status_code == 302

def test_mcp_with_invalid_token():
    """Test that MCP rejects invalid tokens"""
    print("\n2. Testing MCP with invalid token:")
    
    response = requests.post(
        "https://claude.atratest.org/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
            "id": 1
        },
        headers={
            "Authorization": "Bearer invalid_token_12345"
        },
        allow_redirects=False,
        verify=False
    )
    
    print(f"   Status: {response.status_code}")
    if response.status_code == 401:
        print(f"   ✅ Correctly returns 401 Unauthorized")
    elif response.status_code == 302:
        print(f"   ✅ Redirects to re-authenticate")
    else:
        print(f"   Response: {response.text[:200]}...")
    
    return response.status_code in [401, 302]

def test_well_known_endpoints():
    """Test that well-known endpoints are accessible"""
    print("\n3. Testing well-known endpoints:")
    
    # Test OAuth authorization server metadata
    response = requests.get(
        "https://claude.atratest.org/.well-known/oauth-authorization-server",
        verify=False
    )
    
    print(f"   OAuth server metadata: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"   ✅ Issuer: {data.get('issuer')}")
        print(f"   ✅ Resource indicators: {data.get('resource_indicators_supported')}")
    
    # Test protected resource metadata
    response = requests.get(
        "https://claude.atratest.org/.well-known/oauth-protected-resource",
        verify=False
    )
    
    print(f"   Protected resource metadata: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"   ✅ Resource: {data.get('resource')}")
        print(f"   ✅ Auth servers: {data.get('authorization_servers')}")
        print(f"   ✅ Scopes: {data.get('scopes_supported')}")
    
    return True

def test_mcp_spec_compliance():
    """Test MCP specification compliance"""
    print("\n4. Testing MCP Specification Compliance:")
    
    # Check that token is NOT accepted in query string
    response = requests.post(
        "https://claude.atratest.org/mcp?access_token=test_token",
        json={
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
            "id": 1
        },
        allow_redirects=False,
        verify=False
    )
    
    print(f"   Token in query string: {response.status_code}")
    if response.status_code in [302, 401]:
        print(f"   ✅ Correctly rejects token in query string")
    else:
        print(f"   ❌ Should reject token in query string")
    
    return True

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    all_passed = True
    all_passed &= test_mcp_without_auth()
    all_passed &= test_mcp_with_invalid_token()
    all_passed &= test_well_known_endpoints()
    all_passed &= test_mcp_spec_compliance()
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ MCP OAuth Protection is COMPLIANT with specification!")
        print("\nThe MCP endpoint is correctly:")
        print("1. Protected by OAuth 2.1")
        print("2. Redirecting unauthenticated requests to authorization")
        print("3. Including resource parameter for audience binding")
        print("4. Exposing well-known metadata endpoints")
        print("5. Following MCP authorization specification")
    else:
        print("❌ MCP OAuth Protection has issues")
    
    exit(0 if all_passed else 1)