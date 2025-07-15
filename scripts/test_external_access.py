#!/usr/bin/env python
"""Test if external services can reach us reliably."""

import subprocess
import os

def main():
    test_domain = os.getenv("TEST_DOMAIN")
    assert test_domain)
    
    # Test IPv4
    print("\n1. Testing IPv4 connectivity:")
    result = subprocess.run(
        ["curl", "-4", "-v", "--max-time", "10", f"http://{test_domain}/.well-known/acme-challenge/test"],
        capture_output=True,
        text=True
    )
    print(f"Exit code: {result.returncode}")
    if result.returncode == 0:
        print("✓ IPv4 works")
    else:
        print("✗ IPv4 failed")
        print(result.stderr)
    
    # Test IPv6
    print("\n2. Testing IPv6 connectivity:")
    result = subprocess.run(
        ["curl", "-6", "-v", "--max-time", "10", f"http://{test_domain}/.well-known/acme-challenge/test"],
        capture_output=True,
        text=True
    )
    print(f"Exit code: {result.returncode}")
    if result.returncode == 0:
        print("✓ IPv6 works")
    else:
        print("✗ IPv6 failed (this might be the issue!)")
        print(result.stderr[:500])
    
    # Check DNS
    print("\n3. Checking DNS records:")
    subprocess.run(["nslookup", test_domain])

if __name__ == "__main__":
    main()