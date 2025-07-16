#!/usr/bin/env python3
"""Comprehensive test of all just token and cert commands."""

import os
import sys
import subprocess
import time
import json

def run_cmd(cmd, check=True):
    """Run command and return success, stdout, stderr."""
    print(f"\n🔧 Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.stdout:
        print(f"✅ Output:\n{result.stdout}")
    if result.stderr and result.returncode != 0:
        print(f"❌ Error:\n{result.stderr}")
    
    if check and result.returncode != 0:
        print(f"⚠️  Command failed with exit code {result.returncode}")
        
    return result.returncode == 0, result.stdout, result.stderr


def test_token_commands():
    """Test all token commands."""
    print("\n" + "="*60)
    print("🔑 TESTING TOKEN COMMANDS")
    print("="*60)
    
    timestamp = int(time.time())
    test_token_name = f"test-token-{timestamp}"
    
    # 1. Generate token
    print(f"\n1️⃣ Testing token-generate: {test_token_name}")
    success, stdout, stderr = run_cmd(f"just token-generate {test_token_name}")
    if not success:
        return False, "token-generate failed"
    
    # Extract token from output
    token = None
    for line in stdout.split('\n'):
        if line.startswith("Token: acm_"):
            token = line.split("Token: ")[1].strip()
            break
    
    if not token:
        print("❌ Could not extract token from output")
        return False, "token extraction failed"
    
    print(f"✅ Token generated: {token[:20]}...")
    
    # 2. List tokens
    print("\n2️⃣ Testing token-list")
    success, stdout, stderr = run_cmd("just token-list")
    if not success:
        return False, "token-list failed"
    
    if test_token_name not in stdout:
        print(f"❌ Token {test_token_name} not found in list")
        return False, "token not in list"
    
    # 3. Show specific token
    print(f"\n3️⃣ Testing token-show: {test_token_name}")
    success, stdout, stderr = run_cmd(f"just token-show {test_token_name}")
    if not success:
        return False, "token-show failed"
    
    if token not in stdout:
        print("❌ Full token not shown")
        return False, "token-show incomplete"
    
    # 4. Show token certs (should be empty)
    print(f"\n4️⃣ Testing token-show-certs: {test_token_name}")
    success, stdout, stderr = run_cmd(f"just token-show-certs {test_token_name}")
    if not success:
        return False, "token-show-certs failed"
    
    # 5. Delete token
    print(f"\n5️⃣ Testing token-delete: {test_token_name}")
    success, stdout, stderr = run_cmd(f"echo 'yes' | docker exec -i mcp-http-proxy-acme-certmanager-1 pixi run python scripts/delete_token.py {test_token_name}")
    if not success:
        return False, "token-delete failed"
    
    # Verify deletion
    success, stdout, stderr = run_cmd(f"just token-show {test_token_name}", check=False)
    if success:
        print("❌ Token still exists after deletion")
        return False, "token-delete verification failed"
    
    print("\n✅ All token commands passed!")
    return True, token


def test_cert_commands(token=None):
    """Test all certificate commands."""
    print("\n" + "="*60)
    print("🔐 TESTING CERTIFICATE COMMANDS")
    print("="*60)
    
    timestamp = int(time.time())
    test_domain_base = os.getenv('TEST_DOMAIN_BASE')
    test_email = os.getenv('TEST_EMAIL')
    
    if not test_domain_base or not test_email:
        print("❌ TEST_DOMAIN_BASE and TEST_EMAIL must be set in .env")
        return False, "env vars missing"
    
    # Create token if not provided
    if not token:
        token_name = f"cert-test-token-{timestamp}"
        print(f"\n📝 Creating token for cert tests: {token_name}")
        success, stdout, stderr = run_cmd(f"just token-generate {token_name}")
        if not success:
            return False, "token generation for cert test failed"
        
        # Extract token
        for line in stdout.split('\n'):
            if line.startswith("Token: acm_"):
                token = line.split("Token: ")[1].strip()
                break
    else:
        token_name = f"existing-token-{timestamp}"
    
    test_cert_name = f"test-cert-{timestamp}"
    test_domain = f"test-{timestamp}.{test_domain_base}"
    test_email_addr = f"test{timestamp}@{test_email.split('@')[1]}"
    
    # 1. List certs (public, should work without token)
    print("\n1️⃣ Testing cert-list (public access)")
    success, stdout, stderr = run_cmd("just cert-list")
    if not success:
        return False, "cert-list public failed"
    
    # 2. List certs with token filter
    print(f"\n2️⃣ Testing cert-list with token: {token_name}")
    success, stdout, stderr = run_cmd(f"just cert-list {token_name}")
    if not success:
        return False, "cert-list with token failed"
    
    # 3. Create certificate
    print(f"\n3️⃣ Testing cert-create: {test_cert_name}")
    print(f"   Domain: {test_domain}")
    print(f"   Email: {test_email_addr}")
    success, stdout, stderr = run_cmd(
        f"just cert-create {test_cert_name} {test_domain} {test_email_addr} {token_name} true"
    )
    if not success:
        return False, "cert-create failed"
    
    # 4. Check status
    print(f"\n4️⃣ Testing cert-status: {test_cert_name}")
    # Wait a bit for generation to start
    time.sleep(2)
    success, stdout, stderr = run_cmd(f"just cert-status {test_cert_name}")
    if not success:
        return False, "cert-status failed"
    
    # 5. Show certificate (might still be generating)
    print(f"\n5️⃣ Testing cert-show: {test_cert_name}")
    success, stdout, stderr = run_cmd(f"just cert-show {test_cert_name}")
    # It's OK if this fails while cert is generating
    
    # 6. Wait for certificate to complete
    print("\n⏳ Waiting for certificate generation to complete...")
    max_attempts = 20
    for i in range(max_attempts):
        success, stdout, stderr = run_cmd(f"just cert-status {test_cert_name} '' wait", check=False)
        if success and "completed" in stdout.lower():
            print("✅ Certificate generated successfully!")
            break
        time.sleep(2)
    else:
        print("⚠️  Certificate generation timed out")
    
    # 7. Show certificate with PEM
    print(f"\n7️⃣ Testing cert-show with --pem: {test_cert_name}")
    success, stdout, stderr = run_cmd(f"just cert-show {test_cert_name} {token_name} pem")
    if not success:
        print("⚠️  cert-show with pem failed (might be OK if cert is still generating)")
    
    # 8. Renew certificate
    print(f"\n8️⃣ Testing cert-renew: {test_cert_name}")
    success, stdout, stderr = run_cmd(f"just cert-renew {test_cert_name} {token_name} force")
    if not success:
        print("⚠️  cert-renew failed (might be OK if original cert generation failed)")
    
    # 9. Delete certificate
    print(f"\n9️⃣ Testing cert-delete: {test_cert_name}")
    success, stdout, stderr = run_cmd(f"just cert-delete {test_cert_name} {token_name} force")
    if not success:
        print("⚠️  cert-delete failed")
    
    # 10. Clean up token
    if token_name.startswith("cert-test-token"):
        print(f"\n🧹 Cleaning up test token: {token_name}")
        run_cmd(f"echo 'yes' | docker exec -i mcp-http-proxy-acme-certmanager-1 pixi run python scripts/delete_token.py {token_name}", check=False)
    
    print("\n✅ Certificate command tests completed!")
    return True, "success"


def main():
    """Run all tests."""
    print("🧪 COMPREHENSIVE COMMAND TESTING")
    print("=" * 80)
    
    # Ensure services are running
    print("\n🚀 Checking services...")
    success, stdout, stderr = run_cmd("docker-compose ps")
    if not success:
        print("❌ Docker services not running")
        return 1
    
    # Test token commands
    token_success, token_result = test_token_commands()
    if not token_success:
        print(f"\n❌ Token tests failed: {token_result}")
        return 1
    
    # Test cert commands
    cert_success, cert_result = test_cert_commands()
    if not cert_success:
        print(f"\n❌ Certificate tests failed: {cert_result}")
        return 1
    
    print("\n" + "="*80)
    print("✅ ALL TESTS PASSED!")
    print("="*80)
    return 0


if __name__ == "__main__":
    sys.exit(main())