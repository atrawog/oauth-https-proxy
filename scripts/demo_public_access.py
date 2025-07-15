#!/usr/bin/env python3
"""Demo script showing public certificate access."""

import os
import sys
import time

def demo():
    """Demonstrate public certificate access."""
    print("🔍 ACME Certificate Manager - Public Access Demo\n")
    print("This demo shows how certificate information is publicly accessible")
    print("while certificate management operations require authentication.\n")
    
    print("=" * 60)
    print("1. PUBLIC ACCESS - No authentication required")
    print("=" * 60)
    
    print("\n📋 Listing all certificates (public):")
    print("   Command: just cert-list")
    os.system("just cert-list")
    
    time.sleep(2)
    
    print("\n📄 Viewing certificate details (public):")
    print("   Command: just cert-show production")
    print("   (Replace 'production' with an actual certificate name)\n")
    
    print("=" * 60)
    print("2. AUTHENTICATED ACCESS - Token required")
    print("=" * 60)
    
    print("\n🔐 Operations that require authentication:")
    print("   ✗ just cert-create    - Create new certificate")
    print("   ✗ just cert-delete    - Delete certificate")
    print("   ✗ just cert-renew     - Renew certificate")
    
    print("\n💡 To perform authenticated operations:")
    print("   1. Generate a token: just token-generate mytoken")
    print("   2. Use token in commands: just cert-create test test.com admin@test.com mytoken")
    
    print("\n=" * 60)
    print("3. WEB GUI ACCESS")
    print("=" * 60)
    
    print("\n🌐 The web GUI is available at: http://localhost:80")
    print("   - Public users can browse certificates")
    print("   - Login with token to manage certificates")
    
    print("\n✅ Demo complete!")
    print("\nKey takeaways:")
    print("- Certificate information is publicly readable")
    print("- Certificate management requires authentication")
    print("- Both CLI and web GUI follow the same access model")


if __name__ == "__main__":
    demo()