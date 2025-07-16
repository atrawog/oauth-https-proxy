#!/usr/bin/env python3
"""Update a proxy target."""

import sys
import os
import requests
import json
import argparse

def update_proxy_target(hostname: str, token: str, target_url: str = None, 
                       preserve_host: bool = None, custom_headers: str = None,
                       enable_http: bool = None, enable_https: bool = None):
    """Update a proxy target."""
    if not all([hostname, token]):
        print("Error: Hostname and token are required")
        return False
    
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Build update data
    data = {}
    if target_url is not None:
        data["target_url"] = target_url
    if preserve_host is not None:
        data["preserve_host_header"] = preserve_host
    if enable_http is not None:
        data["enable_http"] = enable_http
    if enable_https is not None:
        data["enable_https"] = enable_https
    if custom_headers is not None:
        try:
            data["custom_headers"] = json.loads(custom_headers)
        except json.JSONDecodeError:
            print("Error: custom_headers must be valid JSON")
            return False
    
    if not data:
        print("Error: No fields to update")
        return False
    
    try:
        response = requests.put(
            f"{base_url}/proxy/targets/{hostname}",
            json=data,
            headers=headers
        )
        
        if response.status_code == 200:
            proxy = response.json()
            print(f"✓ Proxy target updated successfully")
            print(f"  Hostname: {proxy.get('hostname')}")
            print(f"  Target URL: {proxy.get('target_url')}")
            print(f"  Certificate: {proxy.get('cert_name')}")
            print(f"  Enabled: {proxy.get('enabled', True)}")
            print(f"  HTTP Enabled: {proxy.get('enable_http', True)}")
            print(f"  HTTPS Enabled: {proxy.get('enable_https', True)}")
            print(f"  Preserve Host: {proxy.get('preserve_host_header', True)}")
            
            custom_hdrs = proxy.get('custom_headers')
            if custom_hdrs:
                print("  Custom Headers:")
                for key, value in custom_hdrs.items():
                    print(f"    {key}: {value}")
            
            return True
        elif response.status_code == 404:
            print(f"✗ Proxy target '{hostname}' not found")
            return False
        elif response.status_code == 403:
            print(f"✗ Access denied - you don't own this proxy target")
            return False
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to update proxy target: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Update a proxy target')
    parser.add_argument('hostname', help='Hostname of the proxy target')
    parser.add_argument('token', help='API token for authentication')
    parser.add_argument('--target-url', help='New target URL')
    parser.add_argument('--preserve-host', help='Preserve host header (true/false)')
    parser.add_argument('--enable-http', help='Enable HTTP (true/false)')
    parser.add_argument('--enable-https', help='Enable HTTPS (true/false)')
    parser.add_argument('--custom-headers', help='Custom headers as JSON string')
    
    args = parser.parse_args()
    
    # Convert booleans if provided
    preserve_host = None
    if args.preserve_host:
        preserve_host = args.preserve_host.lower() in ['true', '1', 'yes']
    
    enable_http = None
    if args.enable_http:
        enable_http = args.enable_http.lower() in ['true', '1', 'yes']
        
    enable_https = None
    if args.enable_https:
        enable_https = args.enable_https.lower() in ['true', '1', 'yes']
    
    if not update_proxy_target(
        args.hostname, 
        args.token,
        args.target_url,
        preserve_host,
        args.custom_headers,
        enable_http,
        enable_https
    ):
        sys.exit(1)