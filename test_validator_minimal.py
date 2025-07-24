#!/usr/bin/env python3
"""Minimal test to identify where validator is hanging"""

import asyncio
import httpx
from mcp_http_validator.validator import MCPValidator

async def test_minimal():
    print("Starting minimal validator test...")
    
    # Test 1: Create validator
    print("\n1. Creating validator...")
    try:
        validator = MCPValidator(
            "https://docs.mcp.cloudflare.com/sse",
            timeout=5.0
        )
        print("Validator created successfully")
    except Exception as e:
        print(f"Failed to create validator: {e}")
        return
    
    # Test 2: Run a single test
    print("\n2. Running transport test...")
    try:
        async with validator:
            result = await validator.test_http_transport()
            print(f"Transport test result: {result[0]}")
            print(f"Message: {result[1]}")
    except Exception as e:
        print(f"Transport test failed: {e}")
    
    print("\nTest complete")

if __name__ == "__main__":
    asyncio.run(test_minimal())