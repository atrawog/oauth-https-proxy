#!/usr/bin/env python
"""Run REAL ACME tests against actual Let's Encrypt staging."""

import os
import sys
import subprocess
import socket


def check_dns_resolution(domain):
    """Check if domain resolves to our IP."""
    try:
        # Get all IPs for domain (IPv4 and IPv6)
        addr_info = socket.getaddrinfo(domain, None)
        ips = set([addr[4][0] for addr in addr_info])
        print(f"✓ {domain} resolves to: {', '.join(ips)}")
        
        # Get our public IPs
        import requests
        try:
            # Try IPv4
            try:
                public_ipv4 = requests.get('https://ipv4.icanhazip.com', timeout=5).text.strip()
                print(f"  Our public IPv4: {public_ipv4}")
            except:
                public_ipv4 = None
            
            # Try IPv6
            try:
                public_ipv6 = requests.get('https://ipv6.icanhazip.com', timeout=5).text.strip()
                print(f"  Our public IPv6: {public_ipv6}")
            except:
                public_ipv6 = None
            
            # Check if any of our IPs match
            our_ips = set(filter(None, [public_ipv4, public_ipv6]))
            if ips & our_ips:
                print(f"✓ DNS correctly points to this server!")
                return True
            else:
                print(f"⚠️  WARNING: Domain IPs don't match our public IPs")
                print(f"  ACME HTTP-01 challenges require domain to point to this server")
                return False
        except:
            print("  Could not determine public IP")
            return True
    except socket.gaierror:
        print(f"✗ {domain} does not resolve!")
        return False


def main():
    """Run real ACME tests."""
    print("=" * 60)
    print("REAL ACME INTEGRATION TESTS")
    print("Using Let's Encrypt Staging")
    print("=" * 60)
    
    # Set up environment - NO DEFAULTS!
    test_domain = os.getenv("TEST_DOMAIN")
    test_email = os.getenv("TEST_EMAIL")
    
    if not test_domain or not test_email:
        print("ERROR: TEST_DOMAIN and TEST_EMAIL must be set in .env")
        print("       Run via 'just' to load .env properly")
        sys.exit(1)
    
    print(f"\nTest Configuration:")
    print(f"  Domain: {test_domain}")
    print(f"  Email: {test_email}")
    print(f"  ACME: Let's Encrypt Staging")
    
    # Check DNS
    print(f"\nChecking DNS...")
    dns_ok = check_dns_resolution(test_domain)
    
    if not dns_ok:
        print("\n✗ DNS FAILURE: Domain does not point to this server!")
        print("   ACME HTTP-01 challenges REQUIRE domain to point here.")
        print("   Fix your DNS and try again.")
        sys.exit(1)
    
    # Ensure services are running
    print("\nStarting services...")
    subprocess.run(["docker-compose", "up", "-d"])
    
    # Wait for health
    print("\nWaiting for services to be healthy...")
    subprocess.run(["sleep", "10"])
    
    # Run the real tests
    print("\nRunning REAL ACME tests...")
    print("-" * 40)
    
    # All env vars should already be loaded by just
    env = os.environ.copy()
    
    result = subprocess.run(
        ["pixi", "run", "pytest", "tests/test_real_acme.py", "-v", "-s"],
        env=env
    )
    
    print("\n" + "=" * 60)
    if result.returncode == 0:
        print("✓ ALL REAL TESTS PASSED!")
    else:
        print("✗ Some tests failed")
    print("=" * 60)
    
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())