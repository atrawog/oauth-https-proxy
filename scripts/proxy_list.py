#!/usr/bin/env python3
"""List all proxy targets."""

import sys
import os
import requests
from datetime import datetime
from tabulate import tabulate

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_utils import get_api_base_url

def list_proxy_targets(token: str = None):
    """List all proxy targets (optionally filtered by token)."""
    base_url = get_api_base_url()
    if not base_url:
        print("Error: Unable to determine API base URL")
        return False
    
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        response = requests.get(
            f"{base_url}/proxy/targets/",
            headers=headers
        )
        
        if response.status_code == 200:
            proxy_targets = response.json()
            
            if not proxy_targets:
                print("No proxy targets found.")
                print("\nCreate your first proxy target with:")
                print("  just proxy-create <hostname> <target_url> <token>")
                return True
            
            # Prepare data for table
            table_data = []
            for proxy in proxy_targets:
                table_data.append({
                    'Hostname': proxy.get('hostname', 'Unknown'),
                    'Target URL': proxy.get('target_url', 'Unknown'),
                    'Certificate': proxy.get('cert_name', 'N/A'),
                    'Enabled': '✓' if proxy.get('enabled', True) else '✗',
                    'HTTP': '✓' if proxy.get('enable_http', True) else '✗',
                    'HTTPS': '✓' if proxy.get('enable_https', True) else '✗',
                    'Preserve Host': '✓' if proxy.get('preserve_host_header', True) else '✗',
                    'Created': proxy.get('created_at', 'Unknown')[:10] if proxy.get('created_at') else 'Unknown'
                })
            
            # Sort by hostname
            table_data.sort(key=lambda x: x['Hostname'])
            
            if token:
                print(f"\n=== Your Proxy Targets ({len(proxy_targets)} total) ===\n")
            else:
                print(f"\n=== All Proxy Targets ({len(proxy_targets)} total) ===\n")
            
            print(tabulate(table_data, headers='keys', tablefmt='grid'))
            
            # Count disabled targets
            disabled = [p for p in proxy_targets if not p.get('enabled', True)]
            if disabled:
                print(f"\n⚠ Note: {len(disabled)} proxy target(s) are disabled")
            
            # Check for HTTPS-enabled proxies without certificates
            https_no_cert = [p for p in proxy_targets 
                           if p.get('enable_https', True) and not p.get('cert_name')]
            if https_no_cert:
                print(f"\n⚠ WARNING: {len(https_no_cert)} proxy target(s) have HTTPS enabled but no certificate!")
                print("  The following proxies need certificates:")
                for proxy in https_no_cert:
                    print(f"    • {proxy['hostname']}")
                print("\n  To generate certificates:")
                print("    just proxy-cert-generate <hostname>        # Generate new certificate")
                print("    just proxy-cert-attach <hostname> <cert>   # Attach existing certificate")
            
            return True
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to list proxy targets: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    # Token is optional - if provided, shows only your proxy targets
    token = sys.argv[1] if len(sys.argv) > 1 else None
    
    if not list_proxy_targets(token):
        sys.exit(1)