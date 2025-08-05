#!/usr/bin/env python3
"""Test if custom headers are being forwarded through proxy"""
import os
import sys
import requests
import json
from pathlib import Path

# Load environment variables
env_file = Path(__file__).parent.parent / ".env"
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

# Test through localhost:80 with Host header
print("=== Testing proxy header forwarding ===\n")

# Test test-auth.local which forwards to httpbin.org
print("1. Testing test-auth.local -> httpbin.org/headers")
print("   This proxy should add X-HackerOne-Research: atrawog")

try:
    # Make request through proxy on port 80 with Host header
    response = requests.get(
        "http://localhost/headers",
        headers={"Host": "test-auth.local"},
        timeout=10
    )
    
    if response.status_code == 200:
        headers_data = response.json()
        received_headers = headers_data.get("headers", {})
        
        print(f"\nStatus: {response.status_code}")
        print("\nHeaders received by httpbin.org:")
        
        # Look for our custom header (case-insensitive)
        found_header = None
        for header, value in received_headers.items():
            print(f"  {header}: {value}")
            if header.lower() == "x-hackerone-research":
                found_header = value
        
        if found_header:
            print(f"\n✅ SUCCESS: X-HackerOne-Research header found with value: {found_header}")
        else:
            print("\n❌ FAILED: X-HackerOne-Research header not found")
    else:
        print(f"Request failed with status: {response.status_code}")
        print(f"Response: {response.text}")
        
except requests.exceptions.RequestException as e:
    print(f"Request error: {e}")

# Test test-auth2.local as well
print("\n\n2. Testing test-auth2.local -> httpbin.org/headers")

try:
    response = requests.get(
        "http://localhost/headers",
        headers={"Host": "test-auth2.local"},
        timeout=10
    )
    
    if response.status_code == 200:
        headers_data = response.json()
        received_headers = headers_data.get("headers", {})
        
        print(f"\nStatus: {response.status_code}")
        
        # Look for our custom header
        found_header = None
        for header, value in received_headers.items():
            if header.lower() == "x-hackerone-research":
                found_header = value
                break
        
        if found_header:
            print(f"✅ X-HackerOne-Research: {found_header}")
        else:
            print("❌ X-HackerOne-Research header not found")
    else:
        print(f"Request failed with status: {response.status_code}")
        
except requests.exceptions.RequestException as e:
    print(f"Request error: {e}")