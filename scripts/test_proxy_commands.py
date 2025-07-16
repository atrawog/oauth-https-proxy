#!/usr/bin/env python3
"""Test all proxy management commands comprehensively."""

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

def test_all_proxy_commands():
    """Test all proxy-related just commands."""
    print("🧪 Testing All Proxy Commands\n")
    print("=" * 60)
    
    # Test configuration - use timestamp to ensure uniqueness
    timestamp = int(time.time())
    test_domain_base = os.getenv('TEST_DOMAIN_BASE')
    test_email = os.getenv('TEST_EMAIL')
    
    if not test_domain_base or not test_email:
        print("Error: TEST_DOMAIN_BASE and TEST_EMAIL must be set in .env")
        return False
    
    test_email_domain = test_email.split('@')[1]
    
    test_token_name = f"test-proxy-token-{timestamp}"
    test_hostname = f"test-proxy-{timestamp}.{test_domain_base}"
    test_target_url = "http://localhost:8080"
    test_updated_url = "http://localhost:9090"
    test_email = f"test{timestamp}@{test_email_domain}"
    
    # Track test results
    results = []
    token = None
    proxy_created = False
    
    try:
        # 1. Create a test token first
        print(f"\n1️⃣ Creating test token: {test_token_name}...")
        success, stdout, stderr = run_command(f"just token-generate {test_token_name} {test_email}")
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
    
        # 2. Test proxy-list without token (public)
        print("\n2️⃣ Testing proxy-list without token (public access)...")
        success, stdout, stderr = run_command("just proxy-list")
        results.append(("proxy-list (no token)", success))
        
        # 3. Test proxy-list with token
        print("\n3️⃣ Testing proxy-list with token...")
        success, stdout, stderr = run_command(f"just proxy-list {test_token_name}")
        results.append(("proxy-list (with token)", success))
    
        # 4. Test proxy-create
        print("\n4️⃣ Testing proxy-create...")
        success, stdout, stderr = run_command(
            f"just proxy-create {test_hostname} {test_target_url} {test_token_name} true false"
        )
        results.append(("proxy-create", success))
        
        if success:
            proxy_created = True
            # Wait a bit for async certificate generation
            print("   ⏳ Waiting for proxy and certificate creation...")
            time.sleep(5)
            
            # 5. Test proxy-show
            print("\n5️⃣ Testing proxy-show...")
            success, stdout, stderr = run_command(f"just proxy-show {test_hostname}")
            results.append(("proxy-show", success))
            
            # 6. Test proxy-disable
            print("\n6️⃣ Testing proxy-disable...")
            success, stdout, stderr = run_command(f"just proxy-disable {test_hostname} {test_token_name}")
            results.append(("proxy-disable", success))
            
            # 7. Test proxy-enable
            print("\n7️⃣ Testing proxy-enable...")
            success, stdout, stderr = run_command(f"just proxy-enable {test_hostname} {test_token_name}")
            results.append(("proxy-enable", success))
            
            # 8. Test proxy-update
            print("\n8️⃣ Testing proxy-update...")
            success, stdout, stderr = run_command(
                f"just proxy-update {test_hostname} {test_token_name} {test_updated_url} true"
            )
            results.append(("proxy-update", success))
            
            # 9. Test proxy-show-targets without token
            print("\n9️⃣ Testing proxy-show-targets without token...")
            success, stdout, stderr = run_command("just proxy-show-targets")
            results.append(("proxy-show-targets (no token)", success))
            
            # 10. Test proxy-show-targets with token
            print("\n🔟 Testing proxy-show-targets with token...")
            success, stdout, stderr = run_command(f"just proxy-show-targets {test_token_name}")
            results.append(("proxy-show-targets (with token)", success))
            
            # 11. Test proxy-delete (without cert deletion)
            print("\n1️⃣1️⃣ Testing proxy-delete (without cert deletion)...")
            # Use force flag to skip confirmation
            success, stdout, stderr = run_command(
                f"just proxy-delete {test_hostname} {test_token_name} false force"
            )
            results.append(("proxy-delete", success))
            
            proxy_created = False
    
    except Exception as e:
        print(f"\n❌ Test failed with exception: {e}")
        return False
    
    finally:
        # Cleanup
        print("\n🧹 Cleaning up test resources...")
        
        # Delete proxy if still exists
        if proxy_created:
            run_command(f"just proxy-delete {test_hostname} {test_token_name} true force", capture=False)
        
        # Delete token (will cascade delete owned resources)
        if token:
            run_command(f"just token-delete {test_token_name} force", capture=False)
    
    # Print results summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary:")
    print("=" * 60)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return passed == total


if __name__ == "__main__":
    success = test_all_proxy_commands()
    sys.exit(0 if success else 1)