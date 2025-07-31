#!/usr/bin/env python3
"""Test routes module import."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from src.api.routers.v1 import routes
    print("Routes module imported successfully")
    
    # Check if create_router function exists
    if hasattr(routes, 'create_router'):
        print("create_router function found")
    else:
        print("create_router function NOT found")
        
except ImportError as e:
    print(f"Failed to import routes module: {e}")
    import traceback
    traceback.print_exc()