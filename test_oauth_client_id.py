#!/usr/bin/env python3
"""Test OAuth flow to verify correct client_id is used for claude.atratest.org"""

import requests
import re
from urllib.parse import urlparse, parse_qs

def test_oauth_client_id():
    """Test that OAuth flow uses the correct GitHub client ID"""
    
    # Test OAuth authorize endpoint
    test_url = "https://claude.atratest.org/authorize"
    params = {
        "client_id": "client_0ySW-CMkkqwWQ1AasQ2f1Q",
        "response_type": "code",
        "redirect_uri": "https://example.com/callback",
        "state": "test_state"
    }
    
    print(f"Testing OAuth flow for claude.atratest.org...")
    print(f"URL: {test_url}")
    
    # Make request but don't follow redirects
    response = requests.get(test_url, params=params, allow_redirects=False, verify=False)
    
    print(f"Response status: {response.status_code}")
    
    if response.status_code in [302, 307]:
        # Check the redirect location
        location = response.headers.get('location', '')
        print(f"Redirect to: {location}")
        
        # Parse the GitHub OAuth URL
        if 'github.com/login/oauth/authorize' in location:
            parsed = urlparse(location)
            query_params = parse_qs(parsed.query)
            
            client_id = query_params.get('client_id', [''])[0]
            redirect_uri = query_params.get('redirect_uri', [''])[0]
            
            print(f"\nOAuth Configuration:")
            print(f"  Client ID: {client_id}")
            print(f"  Redirect URI: {redirect_uri}")
            
            # Check if it's using the correct client ID
            expected_client_id = "Ov23liTMMd2OWs1jJMdf"
            if client_id == expected_client_id:
                print(f"✅ SUCCESS: Using correct per-proxy GitHub OAuth Client ID!")
            else:
                print(f"❌ FAILURE: Using wrong client ID")
                print(f"   Expected: {expected_client_id}")
                print(f"   Got: {client_id}")
                return False
                
            # Check redirect URI
            if 'claude.atratest.org/callback' in redirect_uri:
                print(f"✅ Redirect URI correctly uses claude.atratest.org")
            else:
                print(f"⚠️  Redirect URI: {redirect_uri}")
                
            return client_id == expected_client_id
            
    else:
        print(f"Unexpected response: {response.status_code}")
        print(f"Response body: {response.text[:500]}")
        return False

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    success = test_oauth_client_id()
    exit(0 if success else 1)