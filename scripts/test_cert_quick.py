#!/usr/bin/env python
"""Quick certificate test."""

import httpx
import json
import os

# Get base URL from .env
base_url = os.getenv("TEST_BASE_URL")
assert base_url, "TEST_BASE_URL must be set in .env"

client = httpx.Client(base_url=base_url, timeout=180)

print("Requesting certificate...")
response = client.post('/certificates', json={
    'domain': 'test.atradev.org',
    'email': 'test@atradev.org',
    'cert_name': 'test-quick',
    'acme_directory_url': os.getenv("ACME_STAGING_URL")
})

print(f"Status: {response.status_code}")
if response.status_code == 200:
    cert = response.json()
    print(f"SUCCESS! Certificate issued for: {cert['domains']}")
    print(f"Expires: {cert['expires_at']}")
    print(f"Certificate valid: {cert['fullchain_pem'].startswith('-----BEGIN CERTIFICATE-----')}")
else:
    print(f"Error: {response.text[:500]}")