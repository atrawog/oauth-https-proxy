#!/usr/bin/env python3
"""Check certificate generation status."""

import sys
import os
import requests
import time

def check_status(cert_name: str, token: str = None, wait: bool = False):
    """Check certificate generation status."""
    if not cert_name:
        print("Error: Certificate name is required")
        return False
    
    base_url = os.getenv('BASE_URL')

    
    if not base_url:

    
        print("Error: BASE_URL must be set in .env")

    
        return False
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        while True:
            response = requests.get(
                f"{base_url}/certificates/{cert_name}/status",
                headers=headers
            )
            
            if response.status_code == 200:
                status_data = response.json()
                status = status_data.get('status', 'unknown')
                message = status_data.get('message', '')
                
                # Display status
                if status == 'in_progress':
                    print(f"⏳ Certificate generation in progress: {message}")
                elif status == 'completed':
                    print(f"✓ Certificate generation completed!")
                    if wait:
                        # Show certificate details
                        print("\nFetching certificate details...")
                        cert_response = requests.get(
                            f"{base_url}/certificates/{cert_name}",
                            headers=headers
                        )
                        if cert_response.status_code == 200:
                            cert = cert_response.json()
                            print(f"  Domains: {', '.join(cert.get('domains', []))}")
                            print(f"  Status: {cert.get('status', 'Unknown')}")
                            if cert.get('expires_at'):
                                print(f"  Expires: {cert['expires_at']}")
                    return True
                elif status == 'failed':
                    print(f"✗ Certificate generation failed: {message}")
                    return False
                elif status == 'not_found':
                    print(f"✗ Certificate '{cert_name}' not found or generation not started")
                    return False
                else:
                    print(f"? Unknown status: {status} - {message}")
                    return False
                
                # If waiting and still in progress, wait and retry
                if wait and status == 'in_progress':
                    time.sleep(5)
                    continue
                else:
                    # Not waiting - return success for in_progress or completed
                    return status in ['in_progress', 'completed']
                    
            else:
                print(f"✗ Failed to check status: {response.status_code}")
                return False
                
    except KeyboardInterrupt:
        print("\n\nStatus check interrupted")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: cert_status.py <cert_name> [token] [--wait]")
        sys.exit(1)
    
    cert_name = sys.argv[1]
    
    # Parse optional arguments
    token = None
    wait = False
    
    for arg in sys.argv[2:]:
        if arg == '--wait':
            wait = True
        elif not token and not arg.startswith('--'):
            token = arg
    
    if not check_status(cert_name, token, wait):
        sys.exit(1)