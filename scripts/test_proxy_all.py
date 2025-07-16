#!/usr/bin/env python3
"""Run all proxy tests comprehensively."""

import os
import sys
import subprocess

def run_test(test_name, script_name):
    """Run a single test script."""
    print(f"\n{'='*60}")
    print(f"Running: {test_name}")
    print('='*60)
    
    result = subprocess.run(
        ["pixi", "run", "python", f"scripts/{script_name}"],
        capture_output=False,
        text=True
    )
    
    return result.returncode == 0


def main():
    """Run all proxy tests."""
    print("COMPREHENSIVE PROXY TEST SUITE")
    print("="*60)
    
    tests = [
        ("Basic Proxy Functionality", "test_proxy_basic.py"),
        ("HTTP Request Forwarding", "test_proxy_requests.py"),
        ("Simple Echo Test", "test_proxy_simple.py"),
        ("WebSocket Proxy", "test_websocket_proxy.py"),
        ("Streaming and SSE", "test_streaming_proxy.py"),
    ]
    
    results = {}
    
    for test_name, script_name in tests:
        # Skip WebSocket and streaming tests if dependencies are missing
        if "websocket" in script_name or "streaming" in script_name:
            try:
                import websockets
                import httpx
            except ImportError:
                print(f"\n⚠️  Skipping {test_name} - missing dependencies")
                continue
        
        success = run_test(test_name, script_name)
        results[test_name] = success
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    total_tests = len(results)
    passed_tests = sum(1 for success in results.values() if success)
    
    for test_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nTotal: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("\n🎉 All proxy tests passed!")
        return 0
    else:
        print(f"\n❌ {total_tests - passed_tests} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())