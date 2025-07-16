#!/usr/bin/env python
"""Test token info endpoint."""

import requests
import os

token = "acm_e5AGpHJd2qxWocqBn6lXDBV_6AvD02R-A6AhdmSK8uA"
base_url = os.getenv("BASE_URL", "http://localhost:8000")

# Test token info endpoint
response = requests.get(
    f"{base_url}/token/info",
    headers={"Authorization": f"Bearer {token}"}
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

if response.ok:
    data = response.json()
    print("\nToken Info:")
    print(f"  Name: {data.get('name')}")
    print(f"  Email: {data.get('cert_email')}")
    print(f"  Hash Preview: {data.get('hash_preview')}")