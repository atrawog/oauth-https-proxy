#!/usr/bin/env python3
"""Debug token info endpoint."""

import os
import sys
import requests

# Configuration
BASE_URL = os.getenv("TEST_BASE_URL", "http://localhost:80")

def debug_token_info(token):
    """Debug the /token/info endpoint."""
    print(f"\n{'='*60}")
    print("DEBUG: Token Info Endpoint")
    print(f"{'='*60}\n")
    
    print(f"Token: {token[:20]}..." if len(token) > 20 else f"Token: {token}")
    print(f"URL: {BASE_URL}/token/info")
    
    headers = {"Authorization": f"Bearer {token}"}
    print(f"\nHeaders: {headers}")
    
    try:
        print("\nMaking request...")
        response = requests.get(f"{BASE_URL}/token/info", headers=headers)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            print(f"\n✅ Success!")
            print(f"Response: {response.json()}")
        else:
            print(f"\n❌ Failed!")
            print(f"Response: {response.text}")
            
        # Try without Bearer prefix
        print(f"\n{'='*40}")
        print("Testing without Bearer prefix...")
        headers2 = {"Authorization": token}
        response2 = requests.get(f"{BASE_URL}/token/info", headers=headers2)
        print(f"Status Code: {response2.status_code}")
        if response2.status_code != 200:
            print(f"Response: {response2.text}")
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    print(f"\n{'='*60}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: debug_token_info.py <token>")
        print("\nExample:")
        print("  debug_token_info.py acm_xxxxx")
        sys.exit(1)
    
    token = sys.argv[1]
    debug_token_info(token)