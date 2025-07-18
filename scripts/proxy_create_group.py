#!/usr/bin/env python3
"""Create a group of proxy targets sharing a single multi-domain certificate."""

import sys
import os
import requests
import time
from typing import List, Dict, Any

def create_proxy_group(
    group_name: str, 
    hostnames: str, 
    target_url: str, 
    token: str, 
    staging: bool = False,
    preserve_host: bool = True
) -> bool:
    """Create multiple proxy targets sharing a single certificate."""
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Parse hostnames
    hostname_list = [h.strip() for h in hostnames.split(',') if h.strip()]
    if not hostname_list:
        print("Error: No valid hostnames provided")
        return False
    
    if len(hostname_list) < 2:
        print("Error: Group creation requires at least 2 hostnames")
        print("       Use 'just proxy-create' for single proxy targets")
        return False
    
    # Certificate name for the group
    cert_name = f"group-{group_name}"
    
    print(f"Creating proxy group '{group_name}'")
    print(f"  Hostnames: {', '.join(hostname_list)}")
    print(f"  Target URL: {target_url}")
    print(f"  Certificate: {cert_name}")
    print(f"  Environment: {'Staging' if staging else 'Production'}")
    print("")
    
    # Get token info for email
    try:
        response = requests.get(f"{base_url}/token/info", headers=headers)
        if response.status_code != 200:
            print("✗ Failed to get token info")
            return False
        
        token_info = response.json()
        email = token_info.get('cert_email')
        if not email:
            print("✗ No certificate email configured for token")
            print("  Set email with: just token-email-update <email>")
            return False
    except Exception as e:
        print(f"✗ Error getting token info: {e}")
        return False
    
    # Step 1: Check which proxies already exist
    print("Step 1: Checking existing proxies...")
    existing_proxies = []
    new_proxies = []
    
    for hostname in hostname_list:
        response = requests.get(f"{base_url}/proxy/targets/{hostname}", headers=headers)
        if response.status_code == 200:
            existing_proxies.append(hostname)
            print(f"  ⚠ {hostname} - Already exists")
        else:
            new_proxies.append(hostname)
            print(f"  ✓ {hostname} - Will be created")
    
    if not new_proxies and existing_proxies:
        print("\n⚠ All proxies already exist. Consider updating them instead.")
        return False
    
    # Step 2: Create multi-domain certificate
    print(f"\nStep 2: Creating multi-domain certificate '{cert_name}'...")
    
    cert_data = {
        "cert_name": cert_name,
        "domains": hostname_list,
        "email": email,
        "acme_directory_url": (
            "https://acme-staging-v02.api.letsencrypt.org/directory" if staging
            else "https://acme-v02.api.letsencrypt.org/directory"
        )
    }
    
    try:
        response = requests.post(
            f"{base_url}/certificates/multi-domain",
            json=cert_data,
            headers=headers
        )
        
        if response.status_code == 200:
            print("  ✓ Certificate generation started")
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            
            # Check if certificate already exists
            if response.status_code == 409 or "already exists" in str(error):
                print(f"  ℹ Certificate '{cert_name}' already exists")
                # Check if it covers all our domains
                cert_response = requests.get(f"{base_url}/certificates/{cert_name}", headers=headers)
                if cert_response.status_code == 200:
                    cert = cert_response.json()
                    cert_domains = set(cert.get('domains', []))
                    our_domains = set(hostname_list)
                    if our_domains.issubset(cert_domains):
                        print(f"  ✓ Existing certificate covers all required domains")
                    else:
                        missing = our_domains - cert_domains
                        print(f"  ⚠ Existing certificate missing domains: {', '.join(missing)}")
                        print(f"    Consider creating a new certificate with a different name")
                        return False
            else:
                print(f"  ✗ Failed to create certificate: {error.get('detail', response.text)}")
                return False
    except Exception as e:
        print(f"  ✗ Error creating certificate: {e}")
        return False
    
    # Wait for certificate generation
    print("\n  Waiting for certificate generation...")
    max_attempts = 30
    cert_ready = False
    
    for attempt in range(max_attempts):
        time.sleep(2)
        
        response = requests.get(f"{base_url}/certificates/{cert_name}/status", headers=headers)
        if response.status_code == 200:
            status_data = response.json()
            status = status_data.get('status', 'unknown')
            
            if status == 'completed':
                print("  ✓ Certificate generated successfully")
                cert_ready = True
                break
            elif status == 'failed':
                print(f"  ✗ Certificate generation failed: {status_data.get('message', 'Unknown error')}")
                return False
            else:
                print(f"    ... {status_data.get('message', 'Generating...')}", end='\r')
    
    if not cert_ready:
        # Check if certificate exists anyway (might be from before)
        cert_response = requests.get(f"{base_url}/certificates/{cert_name}", headers=headers)
        if cert_response.status_code == 200:
            print("  ✓ Using existing certificate")
            cert_ready = True
        else:
            print("\n  ✗ Certificate generation timed out")
            return False
    
    # Step 3: Create proxy targets
    print(f"\nStep 3: Creating proxy targets...")
    created_count = 0
    failed_count = 0
    
    for hostname in hostname_list:
        if hostname in existing_proxies:
            print(f"  - {hostname}: Skipped (already exists)")
            continue
        
        proxy_data = {
            "hostname": hostname,
            "target_url": target_url,
            "cert_email": email,
            "acme_directory_url": cert_data["acme_directory_url"],
            "preserve_host_header": preserve_host,
            "enable_https": True,
            "enable_http": True
        }
        
        try:
            response = requests.post(
                f"{base_url}/proxy/targets",
                json=proxy_data,
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"  ✓ {hostname}: Created successfully")
                created_count += 1
            else:
                error = response.json() if response.headers.get('content-type') == 'application/json' else {}
                print(f"  ✗ {hostname}: Failed - {error.get('detail', response.text)}")
                failed_count += 1
        except Exception as e:
            print(f"  ✗ {hostname}: Error - {e}")
            failed_count += 1
    
    # Step 4: Attach certificate to all proxies
    print(f"\nStep 4: Attaching certificate to proxy targets...")
    attached_count = 0
    
    for hostname in hostname_list:
        update_data = {"cert_name": cert_name}
        
        try:
            response = requests.put(
                f"{base_url}/proxy/targets/{hostname}",
                json=update_data,
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"  ✓ {hostname}: Certificate attached")
                attached_count += 1
            else:
                error = response.json() if response.headers.get('content-type') == 'application/json' else {}
                print(f"  ✗ {hostname}: Failed - {error.get('detail', response.text)}")
        except Exception as e:
            print(f"  ✗ {hostname}: Error - {e}")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"Proxy Group Creation Summary")
    print(f"{'='*60}")
    print(f"Group Name: {group_name}")
    print(f"Certificate: {cert_name}")
    print(f"Total Hostnames: {len(hostname_list)}")
    print(f"  - Already Existed: {len(existing_proxies)}")
    print(f"  - Created: {created_count}")
    print(f"  - Failed: {failed_count}")
    print(f"Certificate Attached: {attached_count}/{len(hostname_list)}")
    
    if attached_count == len(hostname_list):
        print(f"\n✅ Proxy group '{group_name}' created successfully!")
        print(f"\nAccess your services:")
        for hostname in hostname_list:
            print(f"  • https://{hostname}/")
    else:
        print(f"\n⚠️  Proxy group '{group_name}' created with warnings")
    
    return attached_count > 0


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: proxy_create_group.py <group_name> <hostnames> <target_url> <token> [staging] [preserve_host]")
        print("")
        print("Create multiple proxy targets sharing a single multi-domain certificate")
        print("")
        print("Arguments:")
        print("  group_name    - Name for this proxy group")
        print("  hostnames     - Comma-separated list of hostnames")
        print("  target_url    - Backend URL to proxy to")
        print("  token         - API token for authentication")
        print("  staging       - Use staging certificates (optional, default: false)")
        print("  preserve_host - Preserve Host header (optional, default: true)")
        print("")
        print("Examples:")
        print('  proxy_create_group.py api-services "api.example.com,api-v2.example.com" http://api:3000 $TOKEN')
        print('  proxy_create_group.py test-apps "app1.test.com,app2.test.com,app3.test.com" http://app:8080 $TOKEN staging')
        sys.exit(1)
    
    group_name = sys.argv[1]
    hostnames = sys.argv[2]
    target_url = sys.argv[3]
    token = sys.argv[4]
    staging = len(sys.argv) > 5 and sys.argv[5].lower() in ['staging', 'true', '1']
    preserve_host = len(sys.argv) <= 6 or sys.argv[6].lower() not in ['false', '0']
    
    if not create_proxy_group(group_name, hostnames, target_url, token, staging, preserve_host):
        sys.exit(1)