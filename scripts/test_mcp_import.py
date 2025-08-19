#!/usr/bin/env python3
"""Test MCP imports."""

try:
    import mcp
    print("✓ mcp module imported")
    
    import mcp.server
    print("✓ mcp.server module imported")
    
    from mcp.server import FastMCP
    print("✓ FastMCP imported")
    
    print("\nMCP is properly installed and importable!")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
    import sys
    print(f"\nPython path:")
    for p in sys.path:
        print(f"  {p}")