#!/usr/bin/env python3
"""Debug certificate list API response."""

import os
import requests
import json

base_url = os.getenv('BASE_URL')
if not base_url:
    print("Error: BASE_URL not set")
    exit(1)

print(f"Fetching certificates from: {base_url}/certificates")

response = requests.get(f"{base_url}/certificates")
print(f"\nStatus Code: {response.status_code}")
print(f"Headers: {dict(response.headers)}")
print("\nRaw Response:")
print(response.text)

if response.status_code == 200:
    try:
        data = response.json()
        print(f"\nParsed JSON ({len(data)} items):")
        for i, cert in enumerate(data):
            print(f"\n--- Certificate {i+1} ---")
            print(json.dumps(cert, indent=2))
    except Exception as e:
        print(f"\nError parsing JSON: {e}")