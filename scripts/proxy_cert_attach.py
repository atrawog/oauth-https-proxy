#!/usr/bin/env python3
"""Attach an existing certificate to a proxy target."""

import sys
import os
import requests

def attach_certificate_to_proxy(hostname: str, cert_name: str, token: str):
    """Attach an existing certificate to a proxy target."""
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Check if proxy exists
        response = requests.get(f"{base_url}/proxy/targets/{hostname}", headers=headers)
        if response.status_code == 404:
            print(f"✗ Proxy target {hostname} not found")
            return False
        elif response.status_code != 200:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to get proxy target: {error.get('detail', response.text)}")
            return False
        
        proxy = response.json()
        
        # Check if certificate exists
        response = requests.get(f"{base_url}/certificates/{cert_name}", headers=headers)
        if response.status_code == 404:
            print(f"✗ Certificate {cert_name} not found")
            print("\nAvailable certificates:")
            
            # List available certificates
            response = requests.get(f"{base_url}/certificates", headers=headers)
            if response.status_code == 200:
                certs = response.json()
                if certs:
                    for cert in certs:
                        domains = ", ".join(cert.get('domains', []))
                        env = "Staging" if "staging" in cert.get('acme_directory_url', '') else "Production"
                        print(f"  • {cert['cert_name']} - {domains} ({env})")
                else:
                    print("  (No certificates found)")
            return False
        elif response.status_code != 200:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to get certificate: {error.get('detail', response.text)}")
            return False
        
        cert = response.json()
        
        # Check if hostname matches certificate domains
        cert_domains = cert.get('domains', [])
        hostname_matched = False
        
        # Check for exact match
        if hostname in cert_domains:
            hostname_matched = True
        else:
            # Check for wildcard match
            for domain in cert_domains:
                if domain.startswith('*.'):
                    # Wildcard domain like *.example.com
                    wildcard_base = domain[2:]  # Remove *.
                    if hostname.endswith(wildcard_base):
                        # Check that hostname is a subdomain, not the base domain
                        if hostname != wildcard_base and hostname.endswith('.' + wildcard_base):
                            hostname_matched = True
                            break
        
        if not hostname_matched:
            print(f"⚠ Warning: Hostname '{hostname}' does not match certificate domains: {', '.join(cert_domains)}")
            print("  The certificate may not work properly for this hostname.")
            print("  Continue anyway? (y/N): ", end='')
            if input().lower() != 'y':
                print("Cancelled.")
                return False
        
        # Show certificate info
        print(f"\nCertificate details:")
        print(f"  Name: {cert['cert_name']}")
        print(f"  Domains: {', '.join(cert_domains)}")
        print(f"  Environment: {'Staging' if 'staging' in cert.get('acme_directory_url', '') else 'Production'}")
        print(f"  Status: {cert.get('status', 'Unknown')}")
        
        # Update proxy with certificate
        print(f"\nAttaching certificate to proxy {hostname}...")
        
        update_data = {"cert_name": cert_name}
        response = requests.put(
            f"{base_url}/proxy/targets/{hostname}",
            json=update_data,
            headers=headers
        )
        
        if response.status_code == 200:
            updated_proxy = response.json()
            print(f"✓ Successfully attached certificate '{cert_name}' to proxy '{hostname}'")
            
            # Show current proxy status
            print(f"\nProxy configuration:")
            print(f"  Hostname: {updated_proxy['hostname']}")
            print(f"  Target URL: {updated_proxy['target_url']}")
            print(f"  Certificate: {updated_proxy.get('cert_name', '(none)')}")
            print(f"  HTTPS Enabled: {'Yes' if updated_proxy.get('enable_https', True) else 'No'}")
            
            return True
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to update proxy: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: proxy_cert_attach.py <hostname> <cert_name> <token>")
        print("")
        print("Examples:")
        print("  proxy_cert_attach.py api.example.com proxy-api-example-com admin-token")
        print("  proxy_cert_attach.py sub.example.com wildcard-example-com admin-token")
        sys.exit(1)
    
    hostname = sys.argv[1]
    cert_name = sys.argv[2]
    token = sys.argv[3]
    
    if not attach_certificate_to_proxy(hostname, cert_name, token):
        sys.exit(1)