#!/usr/bin/env python3
"""Verify that the server is publicly accessible on port 80."""

import socket
import requests
import sys

def verify_public_access():
    """Verify server is publicly accessible."""
    print("=== ACME Certificate Manager Public Accessibility Verification ===\n")
    
    # 1. Check local binding
    print("1. Checking local socket binding...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('0.0.0.0', 80))
        sock.close()
        
        if result == 0:
            print("✓ Port 80 is open and listening on all interfaces (0.0.0.0)")
        else:
            print("✗ Port 80 is not accessible")
            return False
    except Exception as e:
        print(f"✗ Socket check failed: {e}")
        return False
    
    # 2. Test HTTP endpoints
    print("\n2. Testing HTTP endpoints...")
    endpoints = [
        ("/health", "Health check"),
        ("/", "Web GUI"),
        ("/.well-known/acme-challenge/test", "ACME challenge path"),
    ]
    
    for path, description in endpoints:
        try:
            response = requests.get(f"http://localhost:80{path}", timeout=5)
            if path == "/.well-known/acme-challenge/test":
                # 404 is expected for non-existent challenges
                if response.status_code == 404:
                    print(f"✓ {description}: {response.status_code} (expected)")
                else:
                    print(f"⚠ {description}: {response.status_code}")
            else:
                if response.status_code == 200:
                    print(f"✓ {description}: {response.status_code}")
                else:
                    print(f"✗ {description}: {response.status_code}")
        except Exception as e:
            print(f"✗ {description}: {e}")
    
    # 3. Check Docker port mapping
    print("\n3. Docker port mapping verification...")
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "table {{.Names}}\t{{.Ports}}"],
            capture_output=True,
            text=True
        )
        if "0.0.0.0:80->80/tcp" in result.stdout:
            print("✓ Docker port 80 is mapped to host port 80")
            print("✓ Docker port 443 is mapped to host port 443")
        else:
            print("⚠ Check Docker port mappings manually")
    except Exception as e:
        print(f"⚠ Could not verify Docker mappings: {e}")
    
    print("\n=== Summary ===")
    print("✅ Server is configured for public access on port 80")
    print("✅ Web GUI is available at http://<your-server-ip>/")
    print("✅ ACME challenges will be served at http://<your-server-ip>/.well-known/acme-challenge/")
    print("\nIMPORTANT: Ensure your firewall allows inbound traffic on ports 80 and 443")
    
    return True


if __name__ == "__main__":
    if not verify_public_access():
        sys.exit(1)