#!/usr/bin/env python3
"""Test that all just commands work properly with authentication."""

import os
import subprocess
import time
import sys

def run_command(cmd):
    """Run a command and return success status and output."""
    print(f"\n🔹 Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Success")
            if result.stdout:
                print(f"   Output: {result.stdout.strip()[:100]}...")
            return True, result.stdout
        else:
            print(f"❌ Failed (exit code: {result.returncode})")
            if result.stderr:
                print(f"   Error: {result.stderr.strip()[:200]}...")
            return False, result.stderr
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False, str(e)

def main():
    print("🔐 Testing Authentication in Just Commands")
    print("=" * 60)
    
    # Check if ADMIN_TOKEN is set
    admin_token = os.environ.get("ADMIN_TOKEN")
    admin_email = os.environ.get("ADMIN_EMAIL") 
    
    if not admin_token:
        print("❌ ADMIN_TOKEN not found in environment")
        return False
    
    if not admin_email:
        print("❌ ADMIN_EMAIL not found in environment")
        return False
        
    print(f"✅ ADMIN_TOKEN found: {admin_token[:20]}...")
    print(f"✅ ADMIN_EMAIL found: {admin_email}")
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: List tokens (no auth required)
    print("\n📋 Test 1: List tokens")
    success, _ = run_command("just token-list")
    if success:
        tests_passed += 1
    else:
        tests_failed += 1
    
    # Test 2: List certificates with default admin token
    print("\n📋 Test 2: List certificates (using default ADMIN_TOKEN)")
    success, _ = run_command("just cert-list")
    if success:
        tests_passed += 1
    else:
        tests_failed += 1
    
    # Test 3: List proxy targets with default admin token
    print("\n📋 Test 3: List proxy targets (using default ADMIN_TOKEN)")
    success, _ = run_command("just proxy-list")
    if success:
        tests_passed += 1
    else:
        tests_failed += 1
    
    # Test 4: List routes with default admin token
    print("\n📋 Test 4: List routes (using default ADMIN_TOKEN)")
    success, _ = run_command("just route-list")
    if success:
        tests_passed += 1
    else:
        tests_failed += 1
    
    # Test 5: Create test certificate with defaults
    print("\n📋 Test 5: Create test certificate (using defaults)")
    test_domain = f"test-{int(time.time())}.example.com"
    success, _ = run_command(f'just cert-create test-auth-cert {test_domain} "" "" staging')
    if success:
        tests_passed += 1
        
        # Clean up
        time.sleep(2)
        run_command('just cert-delete test-auth-cert "" force')
    else:
        tests_failed += 1
    
    # Test 6: Create proxy with explicit token override
    print("\n📋 Test 6: Create proxy with explicit token name")
    test_hostname = f"proxy-test-{int(time.time())}.example.com"
    success, _ = run_command(f'just proxy-create {test_hostname} http://localhost:9999 admin')
    if success:
        tests_passed += 1
        
        # Clean up
        time.sleep(1)
        run_command(f'just proxy-delete {test_hostname} "" "" force')
    else:
        tests_failed += 1
    
    # Test 7: Create route with default admin token
    print("\n📋 Test 7: Create route (using default ADMIN_TOKEN)")
    test_route_path = f"/test-auth-{int(time.time())}/"
    success, _ = run_command(f'just route-create "{test_route_path}" instance localhost')
    if success:
        tests_passed += 1
        
        # Get route ID and delete
        success2, output = run_command("just route-list")
        if success2 and test_route_path in output:
            # Extract route ID from output
            for line in output.split('\n'):
                if test_route_path in line:
                    parts = line.split('|')
                    if len(parts) > 1:
                        route_id = parts[1].strip()
                        run_command(f'just route-delete {route_id}')
                        break
    else:
        tests_failed += 1
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Summary:")
    print(f"   ✅ Passed: {tests_passed}")
    print(f"   ❌ Failed: {tests_failed}")
    print(f"   📈 Total:  {tests_passed + tests_failed}")
    
    if tests_failed == 0:
        print("\n🎉 All tests passed! Authentication system is working correctly.")
        return True
    else:
        print(f"\n⚠️  {tests_failed} tests failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    if not main():
        sys.exit(1)