#!/usr/bin/env python
"""Test if Docker container can be reached via IPv6."""

import subprocess
import os

def main():
    test_domain = os.getenv("TEST_DOMAIN")
    
    print("Testing IPv6 connectivity to Docker container...")
    
    # Get container IP
    result = subprocess.run(
        ["docker", "inspect", "mcp-http-proxy-acme-certmanager-1", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
        capture_output=True,
        text=True
    )
    container_ip = result.stdout.strip()
    print(f"Container IPv4: {container_ip}")
    
    # Check if container has IPv6
    result = subprocess.run(
        ["docker", "inspect", "mcp-http-proxy-acme-certmanager-1", "-f", "{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}"],
        capture_output=True,
        text=True
    )
    container_ipv6 = result.stdout.strip()
    print(f"Container IPv6: {container_ipv6 or 'None'}")
    
    # Check host IPv6
    print("\nHost IPv6 addresses:")
    subprocess.run(["ip", "-6", "addr", "show"])
    
    # Check if domain has AAAA record
    print(f"\nChecking IPv6 (AAAA) record for {test_domain}:")
    result = subprocess.run(
        ["dig", "+short", "AAAA", test_domain],
        capture_output=True,
        text=True
    )
    if result.stdout.strip():
        print(f"AAAA record found: {result.stdout.strip()}")
        print("⚠️  WARNING: Domain has IPv6 but Docker might not support it!")
    else:
        print("No AAAA record found (good - no IPv6 issues)")

if __name__ == "__main__":
    main()