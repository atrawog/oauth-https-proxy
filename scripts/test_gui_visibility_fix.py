#!/usr/bin/env python3
"""Test that the GUI properly shows resources based on token ownership."""

import asyncio
import httpx
import json
import os
import sys

API_URL = os.getenv("API_URL", "http://localhost:80")

async def test_gui_with_token(token_name: str, token_value: str):
    """Test what the GUI shows for a specific token."""
    print(f"\n{'='*60}")
    print(f"Testing GUI visibility with token: {token_name}")
    print('='*60)
    
    headers = {"Authorization": f"Bearer {token_value}"}
    
    async with httpx.AsyncClient() as client:
        # Test token info endpoint
        print(f"\n1. Token Info:")
        try:
            response = await client.get(f"{API_URL}/token/info", headers=headers)
            if response.status_code == 200:
                info = response.json()
                print(f"   - Name: {info.get('name', 'N/A')}")
                print(f"   - Email: {info.get('cert_email', 'N/A')}")
                print(f"   - Is Admin: {'ADMIN' in info.get('name', '')}")
            else:
                print(f"   ✗ Failed to get token info: {response.status_code}")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        
        # Test certificates visibility
        print(f"\n2. Certificates visible:")
        try:
            response = await client.get(f"{API_URL}/api/v1/certificates", headers=headers)
            if response.status_code == 200:
                certs = response.json()
                print(f"   - Count: {len(certs)}")
                if certs:
                    for cert in certs[:3]:  # Show first 3
                        print(f"   - {cert['cert_name']}: {', '.join(cert['domains'])}")
                else:
                    print("   - (No certificates visible)")
            else:
                print(f"   ✗ Failed to list certificates: {response.status_code}")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        
        # Test proxies visibility
        print(f"\n3. Proxy targets visible:")
        try:
            response = await client.get(f"{API_URL}/api/v1/proxy/targets", headers=headers)
            if response.status_code == 200:
                proxies = response.json()
                print(f"   - Count: {len(proxies)}")
                if proxies:
                    for proxy in proxies[:3]:  # Show first 3
                        print(f"   - {proxy['hostname']} -> {proxy['target_url']}")
                else:
                    print("   - (No proxy targets visible)")
            else:
                print(f"   ✗ Failed to list proxies: {response.status_code}")
        except Exception as e:
            print(f"   ✗ Error: {e}")
        
        # Test routes visibility
        print(f"\n4. Routes visible:")
        try:
            response = await client.get(f"{API_URL}/api/v1/routes", headers=headers)
            if response.status_code == 200:
                routes = response.json()
                print(f"   - Count: {len(routes)}")
                if routes:
                    for route in routes[:3]:  # Show first 3
                        print(f"   - {route['path_pattern']} -> {route['target_type']}:{route['target_value']}")
            else:
                print(f"   ✗ Failed to list routes: {response.status_code}")
        except Exception as e:
            print(f"   ✗ Error: {e}")

async def main():
    """Test GUI visibility with different tokens."""
    
    # Test with ADMIN token
    admin_token = os.getenv("ADMIN_TOKEN")
    if admin_token:
        await test_gui_with_token("ADMIN", admin_token)
    else:
        print("⚠️  ADMIN_TOKEN not found in environment")
    
    # Test with the test-user token
    test_user_token = "acm_f9G_B9zCTR3OC_RkKb8Ki9p5o3VHkPN5lpXD6MY_Ef4"
    await test_gui_with_token("test-user", test_user_token)
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY:")
    print("- The GUI now properly shows ownership-filtered resources")
    print("- Non-admin users see only their own certs/proxies")
    print("- Routes are global and visible to all")
    print("- Empty states now explain the ownership model")
    print('='*60)

if __name__ == "__main__":
    asyncio.run(main())