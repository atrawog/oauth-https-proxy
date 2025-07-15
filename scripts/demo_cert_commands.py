#!/usr/bin/env python3
"""Demonstrate certificate management commands."""

def demo_cert_commands():
    """Show all certificate management commands."""
    print("=== Certificate Management Commands ===\n")
    
    print("1. CREATE a certificate:")
    print("   just cert-create <name> <domain> <email> <token-name> [staging]")
    print("   Example: just cert-create my-cert example.com admin@example.com my-token")
    print("   Note: Can use token name instead of full token!")
    
    print("\n2. LIST certificates:")
    print("   just cert-list <token-name>")
    print("   Example: just cert-list my-token")
    
    print("\n3. SHOW certificate details:")
    print("   just cert-show <cert-name> <token> [pem]")
    print("   Example: just cert-show my-cert acm_abc...")
    print("   With PEM: just cert-show my-cert acm_abc... pem")
    
    print("\n4. CHECK generation status:")
    print("   just cert-status <cert-name> [token] [wait]")
    print("   Example: just cert-status my-cert")
    print("   Wait for completion: just cert-status my-cert \"\" wait")
    
    print("\n5. RENEW certificate:")
    print("   just cert-renew <cert-name> <token> [force]")
    print("   Example: just cert-renew my-cert acm_abc...")
    print("   Force renewal: just cert-renew my-cert acm_abc... force")
    
    print("\n6. DELETE certificate:")
    print("   just cert-delete <cert-name> <token> [force]")
    print("   Example: just cert-delete my-cert acm_abc...")
    print("   Skip confirmation: just cert-delete my-cert acm_abc... force")
    
    print("\n=== Key Features ===")
    print("✓ Token name support for cert-create and cert-list")
    print("✓ Automatic status polling with --wait")
    print("✓ Force flags to skip confirmations")
    print("✓ PEM export for certificates and keys")
    print("✓ Expiry warnings in cert-list")
    
    print("\n=== Workflow Example ===")
    print("# 1. Generate a token")
    print("just token-generate my-app")
    print("\n# 2. Create a certificate using token name")
    print("just cert-create prod-cert example.com admin@example.com my-app")
    print("\n# 3. Check status")
    print("just cert-status prod-cert \"\" wait")
    print("\n# 4. List all certificates")
    print("just cert-list my-app")


if __name__ == "__main__":
    demo_cert_commands()