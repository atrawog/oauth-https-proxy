#!/usr/bin/env python3
"""Test web GUI with token authentication."""

import requests
import time
import sys
import json
from urllib.parse import urljoin

def test_webgui(base_url="http://localhost:8080", token=None):
    """Test the web GUI functionality."""
    print(f"Testing Web GUI at {base_url}")
    
    # Test 1: Check if GUI is served
    print("\n1. Testing GUI availability...")
    try:
        response = requests.get(base_url)
        assert response.status_code == 200
        assert "ACME Certificate Manager" in response.text
        assert "Bearer Token" in response.text
        print("✓ GUI is served correctly")
    except Exception as e:
        print(f"✗ Failed to load GUI: {e}")
        return False
    
    # Test 2: Check static files
    print("\n2. Testing static file serving...")
    static_files = ["/static/app.js", "/static/styles.css"]
    for file in static_files:
        try:
            response = requests.get(urljoin(base_url, file))
            assert response.status_code == 200
            print(f"✓ {file} loaded successfully")
        except Exception as e:
            print(f"✗ Failed to load {file}: {e}")
            return False
    
    if not token:
        print("\n⚠ No token provided, skipping authenticated tests")
        print("\nTo test authenticated features, run:")
        print("  just token-generate web-test")
        print("  python scripts/test_webgui.py <token>")
        return True
    
    # Test 3: Test API with authentication
    print(f"\n3. Testing API with token authentication...")
    headers = {"Authorization": f"Bearer {token}"}
    
    # List certificates
    try:
        response = requests.get(urljoin(base_url, "/certificates"), headers=headers)
        assert response.status_code == 200
        certs = response.json()
        print(f"✓ Listed {len(certs)} certificates")
    except Exception as e:
        print(f"✗ Failed to list certificates: {e}")
        return False
    
    # Test 4: Test certificate creation through API
    print("\n4. Testing certificate creation...")
    test_cert = {
        "cert_name": "webgui-test",
        "domain": "webgui-test.example.com",
        "email": "webgui@example.com",
        "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"
    }
    
    try:
        response = requests.post(
            urljoin(base_url, "/certificates"),
            json=test_cert,
            headers=headers
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Certificate generation started: {result['message']}")
            
            # Check status
            time.sleep(2)
            status_response = requests.get(
                urljoin(base_url, f"/certificates/{test_cert['cert_name']}/status"),
                headers=headers
            )
            if status_response.status_code == 200:
                status = status_response.json()
                print(f"✓ Certificate status: {status['status']}")
        else:
            print(f"⚠ Certificate might already exist: {response.status_code}")
    except Exception as e:
        print(f"✗ Failed to create certificate: {e}")
        return False
    
    # Test 5: Test unauthorized access
    print("\n5. Testing unauthorized access...")
    try:
        response = requests.get(urljoin(base_url, "/certificates"))
        assert response.status_code == 401
        print("✓ Unauthorized access properly rejected")
    except AssertionError:
        print(f"✗ Unauthorized access not rejected: {response.status_code}")
        return False
    except Exception as e:
        print(f"✗ Failed to test unauthorized access: {e}")
        return False
    
    print("\n✅ All Web GUI tests passed!")
    print("\nYou can now access the GUI at:")
    print(f"  {base_url}")
    print(f"\nUse this token to login:")
    print(f"  {token}")
    
    return True


if __name__ == "__main__":
    base_url = "http://localhost:8080"
    token = sys.argv[1] if len(sys.argv) > 1 else None
    
    if not test_webgui(base_url, token):
        sys.exit(1)