#!/usr/bin/env python3
"""Test complete OAuth flow to verify the callback doesn't crash"""

import requests
import time
import json

def test_authorize_and_callback():
    """Test OAuth authorize followed by callback with expired state"""
    
    print("=" * 60)
    print("Testing Complete OAuth Flow")
    print("=" * 60)
    
    # Step 1: Call authorize endpoint
    authorize_url = "https://claude.atratest.org/authorize"
    params = {
        "client_id": "client_0ySW-CMkkqwWQ1AasQ2f1Q",
        "response_type": "code",
        "redirect_uri": "https://example.com/callback",
        "state": "test_state_123"
    }
    
    print(f"\n1. Testing authorize endpoint...")
    response = requests.get(authorize_url, params=params, allow_redirects=False, verify=False)
    
    if response.status_code in [302, 307]:
        print(f"   ✅ Authorize redirected correctly (status {response.status_code})")
        location = response.headers.get('location', '')
        print(f"   Redirect to: {location[:100]}...")
        
        # Extract state from GitHub URL
        if 'state=' in location:
            github_state = location.split('state=')[1].split('&')[0]
            print(f"   GitHub state: {github_state}")
        else:
            github_state = "unknown_state"
    else:
        print(f"   ❌ Unexpected response: {response.status_code}")
        return False
    
    # Step 2: Simulate callback with the state (but fake code)
    print(f"\n2. Testing callback with fake code...")
    callback_url = "https://claude.atratest.org/callback"
    callback_params = {
        "code": "fake_github_code_123",
        "state": github_state
    }
    
    response = requests.get(callback_url, params=callback_params, allow_redirects=False, verify=False)
    
    print(f"   Response status: {response.status_code}")
    
    if response.status_code == 500:
        print(f"   ❌ FAILURE: Internal Server Error!")
        print(f"   Response: {response.text[:500]}")
        return False
    elif response.status_code in [302, 307]:
        print(f"   ✅ SUCCESS: Callback handled (redirected)")
        location = response.headers.get('location', '')
        print(f"   Redirect to: {location}")
        # This is expected - GitHub code exchange will fail but shouldn't crash
        return True
    else:
        print(f"   Response: {response.text[:200]}...")
        return response.status_code != 500
    
    return True

def test_direct_callback_no_state():
    """Test callback without any state to ensure it doesn't crash"""
    
    print(f"\n3. Testing callback with no state...")
    callback_url = "https://claude.atratest.org/callback"
    callback_params = {
        "code": "test_code_no_state"
    }
    
    response = requests.get(callback_url, params=callback_params, allow_redirects=False, verify=False)
    
    print(f"   Response status: {response.status_code}")
    
    if response.status_code == 500:
        print(f"   ❌ FAILURE: Internal Server Error!")
        print(f"   Response: {response.text[:500]}")
        return False
    elif response.status_code == 422:
        print(f"   ✅ SUCCESS: Proper validation error")
        return True
    elif response.status_code in [302, 307]:
        print(f"   ✅ SUCCESS: Redirected appropriately")
        return True
    else:
        print(f"   Response: {response.text[:200]}...")
        return True

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    all_passed = True
    all_passed &= test_authorize_and_callback()
    all_passed &= test_direct_callback_no_state()
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ OAuth flow tests passed - No Internal Server Errors!")
    else:
        print("❌ OAuth flow tests failed - Internal Server Errors detected")
    
    exit(0 if all_passed else 1)