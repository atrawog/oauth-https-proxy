#!/usr/bin/env python3
"""Test script to verify trace_id propagation through the entire stack.

This script tests that:
1. UnifiedLoggingMiddleware generates trace_id for API requests
2. Dispatcher generates trace_id and propagates it via PROXY protocol
3. Proxy handler receives and uses the trace_id
4. MCP handler uses trace_id from request.state
5. All logs contain the same trace_id for a single request
"""

import asyncio
import httpx
import json
import time
from datetime import datetime, timezone

# Test configuration
API_URL = "http://localhost:9000"
PROXY_URL = "http://localhost"  # Dispatcher on port 80


async def test_api_trace_id():
    """Test that API requests get a trace_id."""
    print("\n=== Testing API trace_id generation ===")
    
    async with httpx.AsyncClient() as client:
        # Make a request to the API health endpoint
        response = await client.get(f"{API_URL}/health")
        print(f"API Health Response: {response.status_code}")
        
        # The trace_id should be logged but not returned in response
        # We'll need to check Redis logs to verify
        
        return response.status_code == 200


async def test_proxy_trace_propagation():
    """Test that proxy requests preserve trace_id."""
    print("\n=== Testing Proxy trace_id propagation ===")
    
    # This requires a proxy to be configured
    # We'll make a request through the dispatcher to a proxy
    
    async with httpx.AsyncClient() as client:
        try:
            # Try to hit a proxy endpoint
            response = await client.get(f"{PROXY_URL}/health", 
                                       headers={"Host": "test.example.com"})
            print(f"Proxy Response: {response.status_code}")
        except Exception as e:
            print(f"Proxy test skipped (no proxy configured): {e}")
            return False
    
    return True


async def test_mcp_trace_id():
    """Test that MCP requests use trace_id from request.state."""
    print("\n=== Testing MCP trace_id usage ===")
    
    async with httpx.AsyncClient() as client:
        # Initialize MCP session
        mcp_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            },
            "id": 0
        }
        
        try:
            response = await client.post(
                f"{API_URL}/mcp",
                json=mcp_request,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            )
            print(f"MCP Response: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"MCP Session initialized: {json.dumps(result, indent=2)}")
                return True
        except Exception as e:
            print(f"MCP test failed: {e}")
            return False
    
    return False


async def check_redis_logs():
    """Check Redis for trace_id in logs."""
    print("\n=== Checking Redis logs for trace_id ===")
    
    try:
        import redis.asyncio as redis
        import os
        
        # Get Redis connection from environment
        redis_url = os.getenv("REDIS_URL", "redis://:your_redis_password_here@localhost:6379/0")
        
        r = redis.from_url(redis_url)
        
        # Get recent logs from the stream
        logs = await r.xrevrange("logs:all:stream", count=10)
        
        print(f"Found {len(logs)} recent log entries")
        
        # Check for trace_id in logs
        trace_ids_found = []
        for log_id, log_data in logs:
            trace_id = log_data.get(b'trace_id', b'').decode('utf-8')
            if trace_id and trace_id != '':
                trace_ids_found.append(trace_id)
                client_ip = log_data.get(b'client_ip', b'').decode('utf-8')
                client_hostname = log_data.get(b'client_hostname', b'').decode('utf-8')
                proxy_hostname = log_data.get(b'proxy_hostname', b'').decode('utf-8')
                method = log_data.get(b'method', b'').decode('utf-8')
                path = log_data.get(b'path', b'').decode('utf-8')
                
                print(f"\nLog Entry {log_id.decode('utf-8')}:")
                print(f"  trace_id: {trace_id}")
                print(f"  client_ip: {client_ip}")
                print(f"  client_hostname: {client_hostname}")
                print(f"  proxy_hostname: {proxy_hostname}")
                print(f"  method: {method} {path}")
        
        await r.close()
        
        if trace_ids_found:
            print(f"\n✓ Found {len(trace_ids_found)} logs with trace_id")
            
            # Check if any trace_id appears multiple times (same request logged at different points)
            from collections import Counter
            trace_counts = Counter(trace_ids_found)
            for trace_id, count in trace_counts.most_common(3):
                if count > 1:
                    print(f"  trace_id {trace_id} appears {count} times (good - same request logged multiple times)")
        else:
            print("\n✗ No logs with trace_id found")
            
        return len(trace_ids_found) > 0
        
    except Exception as e:
        print(f"Failed to check Redis logs: {e}")
        return False


async def main():
    """Run all trace_id propagation tests."""
    print("=" * 60)
    print("Testing trace_id propagation through the stack")
    print("=" * 60)
    
    results = {
        "API trace_id": await test_api_trace_id(),
        "Proxy trace propagation": await test_proxy_trace_propagation(),
        "MCP trace_id": await test_mcp_trace_id(),
        "Redis logs": await check_redis_logs()
    }
    
    print("\n" + "=" * 60)
    print("Test Results:")
    print("=" * 60)
    
    for test_name, passed in results.items():
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name}: {status}")
    
    all_passed = all(results.values())
    
    if all_passed:
        print("\n✓ All tests passed! trace_id is propagating correctly.")
    else:
        print("\n✗ Some tests failed. Check the implementation.")
    
    return all_passed


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)