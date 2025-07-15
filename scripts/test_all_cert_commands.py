#!/usr/bin/env python3
"""Test all certificate commands comprehensively."""

import os
import sys
import subprocess
import time
import json

def run_command(cmd, capture=True):
    """Run a shell command and return output."""
    print(f"\n🔧 Running: {cmd}")
    if capture:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stdout:
            print(f"   Output: {result.stdout.strip()}")
        if result.stderr:
            print(f"   Error: {result.stderr.strip()}")
        return result.returncode == 0, result.stdout, result.stderr
    else:
        return subprocess.run(cmd, shell=True).returncode == 0, "", ""

def test_all_cert_commands():
    """Test all certificate-related just commands."""
    print("🧪 Testing All Certificate Commands\n")
    print("=" * 60)
    
    # Test configuration - use timestamp to ensure uniqueness
    timestamp = int(time.time())
    test_domain_base = os.getenv('TEST_DOMAIN_BASE')
    test_email = os.getenv('TEST_EMAIL')
    
    if not test_domain_base or not test_email:
        print("Error: TEST_DOMAIN_BASE and TEST_EMAIL must be set in .env")
        return False
    
    test_email_domain = test_email.split('@')[1]
    
    test_token_name = f"test-cert-token-{timestamp}"
    test_cert_name = f"test-cert-cmd-{timestamp}"
    test_domain = f"test-cmd-{timestamp}.{test_domain_base}"
    test_email = f"test{timestamp}@{test_email_domain}"
    
    # Track test results
    results = []
    
    # 1. Create a test token first
    print(f"\n1️⃣ Creating test token: {test_token_name}...")
    success, stdout, stderr = run_command(f"just token-generate {test_token_name}")
    if not success:
        print("❌ Failed to create token")
        print(f"   Error output: {stderr}")
        return False
    
    # Extract the token from output
    token = None
    for line in stdout.split('\n'):
        if line.startswith("Token:"):
            token = line.split("Token:")[1].strip()
            break
    
    if not token:
        print("❌ Could not extract token from output")
        return False
    
    print(f"✅ Token created: {test_token_name}")
    
    # 2. Test cert-list without token (public)
    print("\n2️⃣ Testing cert-list without token (public access)...")
    success, stdout, stderr = run_command("just cert-list")
    results.append(("cert-list (no token)", success))
    
    # 3. Test cert-list with token
    print("\n3️⃣ Testing cert-list with token...")
    success, stdout, stderr = run_command(f"just cert-list {test_token_name}")
    results.append(("cert-list (with token)", success))
    
    # 4. Test cert-create (requires token)
    print("\n4️⃣ Testing cert-create...")
    success, stdout, stderr = run_command(
        f"just cert-create {test_cert_name} {test_domain} {test_email} {test_token_name} true"
    )
    results.append(("cert-create", success))
    
    if success:
        # Wait a bit for async generation and storage
        print("   ⏳ Waiting for certificate generation to start and be stored...")
        time.sleep(5)
        
        # 5. Test cert-status without token
        print("\n5️⃣ Testing cert-status without token...")
        success, stdout, stderr = run_command(f"just cert-status {test_cert_name}")
        results.append(("cert-status (no token)", success))
        
        # 6. Test cert-status with token
        print("\n6️⃣ Testing cert-status with token...")
        success, stdout, stderr = run_command(f"just cert-status {test_cert_name} {token}")
        results.append(("cert-status (with token)", success))
        
        # 7. Test cert-show without token
        print("\n7️⃣ Testing cert-show without token...")
        success, stdout, stderr = run_command(f"just cert-show {test_cert_name}")
        results.append(("cert-show (no token)", success))
        
        # 8. Test cert-show with token
        print("\n8️⃣ Testing cert-show with token...")
        success, stdout, stderr = run_command(f"just cert-show {test_cert_name} {token}")
        results.append(("cert-show (with token)", success))
        
        # 9. Test cert-show with --pem flag
        print("\n9️⃣ Testing cert-show with --pem...")
        success, stdout, stderr = run_command(f"just cert-show {test_cert_name} {token} pem")
        results.append(("cert-show --pem", success))
        
        # 10. Test cert-renew (requires token)
        print("\n🔟 Testing cert-renew...")
        success, stdout, stderr = run_command(f"just cert-renew {test_cert_name} {token} force")
        results.append(("cert-renew", success))
        
        # 11. Test cert-delete (requires token)
        print("\n1️⃣1️⃣ Testing cert-delete...")
        success, stdout, stderr = run_command(f"just cert-delete {test_cert_name} {token} force")
        results.append(("cert-delete", success))
    
    # 12. Clean up - delete test token
    print("\n1️⃣2️⃣ Cleaning up - deleting test token...")
    # Use echo to provide input instead of <<< to avoid TTY issues
    success, stdout, stderr = run_command(f"echo 'yes' | docker exec -i mcp-http-proxy-acme-certmanager-1 pixi run python scripts/delete_token.py {test_token_name}")
    results.append(("cleanup", success))
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {test_name}")
        if success:
            passed += 1
        else:
            failed += 1
    
    print(f"\nTotal: {len(results)} tests")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failed > 0:
        print("\n⚠️  Some tests failed. Check the output above for details.")
        return False
    else:
        print("\n✅ All tests passed!")
        return True


if __name__ == "__main__":
    # Make sure services are running
    print("🚀 Ensuring services are running...")
    run_command("docker-compose ps", capture=False)
    
    if not test_all_cert_commands():
        sys.exit(1)