#!/usr/bin/env python3
"""Test OAuth callback handling to verify error handling"""

import requests
import json

def test_callback_with_invalid_state():
    """Test callback with invalid state parameter"""
    
    test_url = "https://claude.atratest.org/callback"
    params = {
        "code": "test_code_123",
        "state": "invalid_state_that_doesnt_exist"
    }
    
    print(f"Testing callback with invalid state...")
    print(f"URL: {test_url}")
    
    response = requests.get(test_url, params=params, allow_redirects=False, verify=False)
    
    print(f"Response status: {response.status_code}")
    
    if response.status_code == 500:
        print(f"❌ FAILURE: Internal Server Error (500)")
        print(f"Response: {response.text[:500]}")
        return False
    elif response.status_code in [400, 401, 403]:
        print(f"✅ SUCCESS: Proper error handling (status {response.status_code})")
        return True
    elif response.status_code in [302, 307]:
        print(f"✅ SUCCESS: Redirecting (status {response.status_code})")
        location = response.headers.get('location', '')
        print(f"Redirect to: {location}")
        return True
    else:
        print(f"Response: {response.text[:500]}")
        return True

def test_callback_without_code():
    """Test callback without code parameter"""
    
    test_url = "https://claude.atratest.org/callback"
    params = {
        "state": "some_state"
    }
    
    print(f"\nTesting callback without code parameter...")
    print(f"URL: {test_url}")
    
    response = requests.get(test_url, params=params, allow_redirects=False, verify=False)
    
    print(f"Response status: {response.status_code}")
    
    if response.status_code == 500:
        print(f"❌ FAILURE: Internal Server Error (500)")
        print(f"Response: {response.text[:500]}")
        return False
    elif response.status_code in [400, 401, 403]:
        print(f"✅ SUCCESS: Proper error handling (status {response.status_code})")
        return True
    elif response.status_code in [302, 307]:
        print(f"✅ SUCCESS: Redirecting (status {response.status_code})")
        location = response.headers.get('location', '')
        print(f"Redirect to: {location}")
        return True
    else:
        print(f"Response: {response.text[:500]}")
        return True

def test_callback_with_error():
    """Test callback with GitHub error"""
    
    test_url = "https://claude.atratest.org/callback"
    params = {
        "error": "access_denied",
        "error_description": "User denied access"
    }
    
    print(f"\nTesting callback with GitHub error...")
    print(f"URL: {test_url}")
    
    response = requests.get(test_url, params=params, allow_redirects=False, verify=False)
    
    print(f"Response status: {response.status_code}")
    
    if response.status_code == 500:
        print(f"❌ FAILURE: Internal Server Error (500)")
        print(f"Response: {response.text[:500]}")
        return False
    elif response.status_code in [302, 307]:
        print(f"✅ SUCCESS: Redirecting with error (status {response.status_code})")
        location = response.headers.get('location', '')
        print(f"Redirect to: {location}")
        return True
    else:
        print(f"✅ SUCCESS: Handled error (status {response.status_code})")
        return True

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    all_passed = True
    all_passed &= test_callback_with_invalid_state()
    all_passed &= test_callback_without_code()
    all_passed &= test_callback_with_error()
    
    print("\n" + "="*50)
    if all_passed:
        print("✅ All callback tests passed!")
    else:
        print("❌ Some callback tests failed")
    
    exit(0 if all_passed else 1)