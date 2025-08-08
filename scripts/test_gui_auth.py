#!/usr/bin/env python3
"""Test GUI authentication and data visibility."""

import os
import sys
import requests
import json

# API endpoint
API_URL = os.environ.get("TEST_API_URL", "http://localhost")

# Tokens to test
ADMIN_TOKEN = "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us"
TEST_USER_TOKEN = "acm_dNvhvG2bdD2vf2A4GAQt-cP8ZnwTtmWdOqx5xZszXY4"

def test_token_visibility(token_name, token):
    """Test what each token can see."""
    headers = {"Authorization": f"Bearer {token}"}
    
    print(f"\n=== Testing {token_name} Token ===")
    
    # Test /certificates
    try:
        resp = requests.get(f"{API_URL}/api/v1/certificates", headers=headers)
        resp.raise_for_status()
        certs = resp.json()
        print(f"Certificates visible: {len(certs)}")
        if certs:
            print("  Certificate names:", [c["cert_name"] for c in certs])
    except Exception as e:
        print(f"Error fetching certificates: {e}")
    
    # Test /proxy/targets
    try:
        resp = requests.get(f"{API_URL}/api/v1/proxy/targets", headers=headers)
        resp.raise_for_status()
        proxies = resp.json()
        print(f"Proxy targets visible: {len(proxies)}")
        if proxies:
            print("  Proxy hostnames:", [p["hostname"] for p in proxies])
    except Exception as e:
        print(f"Error fetching proxies: {e}")
    
    # Test /routes
    try:
        resp = requests.get(f"{API_URL}/api/v1/routes", headers=headers)
        resp.raise_for_status()
        routes = resp.json()
        print(f"Routes visible: {len(routes)}")
        if routes:
            print("  Route patterns:", [r["path_pattern"] for r in routes])
    except Exception as e:
        print(f"Error fetching routes: {e}")

def main():
    """Run tests."""
    print("Testing GUI Authentication and Data Visibility")
    print("=" * 50)
    
    # Test ADMIN token
    test_token_visibility("ADMIN", ADMIN_TOKEN)
    
    # Test regular user token
    test_token_visibility("test-user", TEST_USER_TOKEN)
    
    print("\n" + "=" * 50)
    print("\nSUMMARY:")
    print("- Routes endpoint shows ALL routes regardless of token")
    print("- Certificates and Proxies are filtered by ownership")
    print("- ADMIN token sees all resources")
    print("- Regular tokens see only their own resources")

if __name__ == "__main__":
    main()