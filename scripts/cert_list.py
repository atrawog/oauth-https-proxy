#!/usr/bin/env python3
"""List all certificates owned by the token."""

import sys
import os
import requests
from datetime import datetime
from tabulate import tabulate

def list_certificates(token: str = None):
    """List all certificates (optionally filtered by token)."""
    api_url = os.getenv('API_URL')

    if not api_url:

        print("Error: API_URL must be set in .env")

        return False
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        response = requests.get(
            f"{api_url}/certificates",
            headers=headers
        )
        
        if response.status_code == 200:
            certificates = response.json()
            
            # Check for in-progress certificates from Redis
            # Get all proxy targets to find certificates being generated
            proxy_response = requests.get(f"{api_url}/proxy/targets", headers=headers)
            in_progress_certs = []
            
            if proxy_response.status_code == 200:
                proxy_targets = proxy_response.json()
                for proxy in proxy_targets:
                    cert_name = proxy.get('cert_name')
                    if cert_name and not any(c['cert_name'] == cert_name for c in certificates):
                        # Check if certificate generation is in progress
                        status_response = requests.get(f"{api_url}/certificates/{cert_name}/status")
                        if status_response.status_code == 200:
                            status = status_response.json()
                            if status.get('status') == 'in_progress':
                                in_progress_certs.append({
                                    'cert_name': cert_name,
                                    'domains': [proxy.get('hostname', 'Unknown')],
                                    'status': 'in_progress',
                                    'message': status.get('message', 'Generating...')
                                })
            
            # Combine completed and in-progress certificates
            all_certs = certificates + in_progress_certs
            
            if not all_certs:
                print("No certificates found.")
                print("\nCreate your first certificate with:")
                print("  just cert-create <name> <domain> <email>")
                return True
            
            # Prepare data for table
            table_data = []
            for cert in all_certs:
                # Determine if this is an in-progress certificate
                is_in_progress = cert.get('status') == 'in_progress'
                
                # Calculate days until expiry (only for completed certs)
                expires = cert.get('expires_at')
                days_left = 'N/A'
                expires_str = 'N/A'
                if expires and not is_in_progress:
                    expires_dt = datetime.fromisoformat(expires.replace('Z', '+00:00'))
                    days_left = (expires_dt - datetime.now(expires_dt.tzinfo)).days
                    expires_str = f"{expires_dt.strftime('%Y-%m-%d')} ({days_left}d)"
                elif is_in_progress:
                    expires_str = 'Generating...'
                
                # Determine environment (staging vs production)
                acme_url = cert.get('acme_directory_url', '')
                if 'staging' in acme_url:
                    env = 'Staging'
                elif 'acme-v02.api.letsencrypt.org' in acme_url:
                    env = 'Production'
                else:
                    env = 'Unknown'
                
                # Get status display
                status = cert.get('status', 'Unknown')
                if is_in_progress:
                    status = '⏳ In Progress'
                elif status == 'active':
                    status = '✓ Active'
                elif status == 'failed':
                    status = '✗ Failed'
                
                table_data.append({
                    'Name': cert.get('cert_name', 'Unknown'),
                    'Domains': ', '.join(cert.get('domains', [])),
                    'Status': status,
                    'Environment': env,
                    'Expires': expires_str,
                    'Email': cert.get('email', 'Unknown') if not is_in_progress else 'N/A'
                })
            
            # Sort by name
            table_data.sort(key=lambda x: x['Name'])
            
            # Count different types
            in_progress_count = len([c for c in table_data if c['Status'] == '⏳ In Progress'])
            active_count = len([c for c in table_data if c['Status'] == '✓ Active'])
            staging_count = len([c for c in table_data if c['Environment'] == 'Staging'])
            
            if token:
                print(f"\n=== Your Certificates ({len(all_certs)} total) ===")
            else:
                print(f"\n=== All Certificates ({len(all_certs)} total) ===")
            
            if in_progress_count > 0:
                print(f"ℹ {in_progress_count} certificate(s) currently generating...")
            
            print()
            print(tabulate(table_data, headers='keys', tablefmt='grid'))
            
            # Check for expiring certificates
            expiring = []
            for c in table_data:
                if c['Status'] == '✓ Active' and isinstance(c.get('Expires'), str) and '(' in c['Expires']:
                    try:
                        days = int(c['Expires'].split('(')[1].split('d')[0])
                        if days < 30:
                            expiring.append(c)
                    except:
                        pass
            
            if expiring:
                print(f"\n⚠ Warning: {len(expiring)} certificate(s) expiring soon!")
                print("  Run 'just cert-renew <name>' to renew")
            
            if staging_count > 0:
                print(f"\nℹ Note: {staging_count} certificate(s) are from staging environment")
            
            return True
        else:
            print(f"✗ Failed to list certificates: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    # Token is optional - if provided, shows only your certs
    token = sys.argv[1] if len(sys.argv) > 1 else None
    
    if not list_certificates(token):
        sys.exit(1)