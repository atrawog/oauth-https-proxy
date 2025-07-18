#!/usr/bin/env python3
"""Show which proxy targets can use a given certificate."""

import sys
import os
import requests
from tabulate import tabulate

def check_domain_match(hostname: str, cert_domains: list) -> str:
    """Check if hostname matches any certificate domain."""
    # Check exact match
    if hostname in cert_domains:
        return "exact"
    
    # Check wildcard match
    for domain in cert_domains:
        if domain.startswith('*.'):
            wildcard_base = domain[2:]  # Remove *.
            if hostname.endswith(wildcard_base):
                # Ensure it's a subdomain, not the base itself
                if hostname != wildcard_base and hostname.endswith('.' + wildcard_base):
                    return f"wildcard ({domain})"
    
    return None


def show_certificate_coverage(cert_name: str, token: str = None):
    """Show which proxy targets can use a certificate."""
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        # Get certificate details
        print(f"Checking certificate: {cert_name}")
        
        cert_response = requests.get(
            f"{base_url}/certificates/{cert_name}",
            headers=headers
        )
        
        if cert_response.status_code == 404:
            print(f"✗ Certificate '{cert_name}' not found")
            return False
        elif cert_response.status_code != 200:
            error = cert_response.json() if cert_response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to get certificate: {error.get('detail', cert_response.text)}")
            return False
        
        cert = cert_response.json()
        cert_domains = cert.get('domains', [])
        
        print(f"\nCertificate domains: {', '.join(cert_domains)}")
        print(f"Status: {cert.get('status', 'Unknown')}")
        print(f"Environment: {'Staging' if 'staging' in cert.get('acme_directory_url', '') else 'Production'}")
        
        # Get all proxy targets
        proxy_response = requests.get(
            f"{base_url}/proxy/targets",
            headers=headers
        )
        
        if proxy_response.status_code != 200:
            error = proxy_response.json() if proxy_response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to get proxy targets: {error.get('detail', proxy_response.text)}")
            return False
        
        proxies = proxy_response.json()
        
        # Check which proxies can use this certificate
        compatible_proxies = []
        incompatible_proxies = []
        
        for proxy in proxies:
            hostname = proxy.get('hostname')
            match_type = check_domain_match(hostname, cert_domains)
            
            if match_type:
                compatible_proxies.append({
                    'Hostname': hostname,
                    'Match Type': match_type,
                    'Current Cert': proxy.get('cert_name', '(none)'),
                    'HTTPS Enabled': '✓' if proxy.get('enable_https', True) else '✗',
                    'Target': proxy.get('target_url', 'Unknown')
                })
            else:
                incompatible_proxies.append({
                    'Hostname': hostname,
                    'Current Cert': proxy.get('cert_name', '(none)'),
                    'HTTPS Enabled': '✓' if proxy.get('enable_https', True) else '✗'
                })
        
        # Show compatible proxies
        if compatible_proxies:
            print(f"\n=== Compatible Proxy Targets ({len(compatible_proxies)}) ===")
            print("These proxies can use this certificate:\n")
            print(tabulate(compatible_proxies, headers='keys', tablefmt='grid'))
            
            # Show which ones need the certificate attached
            need_attachment = [p for p in compatible_proxies if p['Current Cert'] != cert_name]
            if need_attachment:
                print(f"\n💡 {len(need_attachment)} proxy target(s) could benefit from this certificate:")
                for proxy in need_attachment:
                    print(f"   just proxy-cert-attach {proxy['Hostname']} {cert_name}")
        else:
            print("\n⚠️  No proxy targets are compatible with this certificate")
        
        # Show incompatible proxies if requested
        if "--all" in sys.argv and incompatible_proxies:
            print(f"\n=== Incompatible Proxy Targets ({len(incompatible_proxies)}) ===")
            print("These proxies cannot use this certificate:\n")
            print(tabulate(incompatible_proxies, headers='keys', tablefmt='grid'))
        
        # Show efficiency metrics
        if cert_domains:
            total_domains = len(cert_domains)
            used_domains = len([p for p in compatible_proxies if p['Current Cert'] == cert_name])
            print(f"\n📊 Certificate Efficiency:")
            print(f"   Domains in certificate: {total_domains}")
            print(f"   Domains actively used: {used_domains}")
            print(f"   Utilization: {(used_domains/total_domains)*100:.0f}%")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: cert_coverage.py <cert_name> [token]")
        print("")
        print("Shows which proxy targets can use a given certificate")
        print("")
        print("Options:")
        print("  --all  - Also show incompatible proxy targets")
        print("")
        print("Examples:")
        print("  cert_coverage.py echo-services")
        print("  cert_coverage.py wildcard-cert $TOKEN --all")
        sys.exit(1)
    
    cert_name = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else None
    
    if not show_certificate_coverage(cert_name, token):
        sys.exit(1)