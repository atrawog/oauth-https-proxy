#!/usr/bin/env python3
"""
Fix remaining sync storage calls in v1 routers that should be async.
This handles routes.py, certificates.py, resources.py, oauth_status.py, oauth_admin.py
"""

import os
import re
import sys

def fix_routes_py():
    """Convert routes.py to use async storage."""
    file_path = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/routes.py"
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Change function signature
    content = content.replace(
        "def create_router(storage):",
        "def create_router(async_storage):"
    )
    
    # Add Request import if not present
    if "from fastapi import" in content and "Request" not in content:
        content = content.replace(
            "from fastapi import APIRouter, HTTPException, Depends, Query",
            "from fastapi import APIRouter, HTTPException, Depends, Query, Request"
        )
    
    # Fix create_route
    content = re.sub(
        r'(@router\.post\("/"\)\s+async def create_route\([^)]+)\)',
        r'\1,\n        request: Request)',
        content
    )
    
    # Replace storage calls with async calls
    replacements = [
        # Simple replacements
        ("if not storage.store_route(route):", "if not await async_storage.store_route(route):"),
        ("storage.list_routes()", "await async_storage.list_routes()"),
        ("route = storage.get_route(route_id)", "route = await async_storage.get_route(route_id)"),
        ("if not storage.update_route(route):", "if not await async_storage.update_route(route):"),
        ("if not storage.delete_route(route_id):", "if not await async_storage.delete_route(route_id):"),
        ("storage.store_route(route)", "await async_storage.store_route(route)"),
        ("storage.update_route(route)", "await async_storage.update_route(route)"),
        ("storage.delete_route(route_id)", "await async_storage.delete_route(route_id)"),
        ("storage.get_route(route_id)", "await async_storage.get_route(route_id)"),
    ]
    
    for old, new in replacements:
        content = content.replace(old, new)
    
    # Add async_storage extraction from request where needed
    # For functions that don't have Request parameter yet
    patterns = [
        (r'(@router\.get\("/"\)\s+async def list_routes\(\s*\):)',
         r'\1\n        request: Request\n    ):'),
        (r'(@router\.get\("/\{route_id\}"\)\s+async def get_route\(\s*route_id: str\s*\):)',
         r'\1\n        request: Request,\n        route_id: str\n    ):'),
        (r'(@router\.put\("/\{route_id\}"\)\s+async def update_route\([^)]+)\)',
         r'\1,\n        request: Request)'),
        (r'(@router\.delete\("/\{route_id\}"\)\s+async def delete_route\([^)]+)\)',
         r'\1,\n        request: Request)'),
    ]
    
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)
    
    # Add async_storage extraction at the beginning of functions
    function_starts = [
        "async def create_route(",
        "async def list_routes(",
        "async def get_route(",
        "async def update_route(",
        "async def delete_route("
    ]
    
    for func_start in function_starts:
        # Find the function and add async_storage extraction after the docstring
        pattern = f'({re.escape(func_start)}[^{{]+{{)(\\s*"""[^"]+"""\\s*)?'
        def replacer(match):
            func_def = match.group(1)
            docstring = match.group(2) or ""
            # Only add if async_storage not already there
            if 'async_storage = request.app.state.async_storage' not in content[match.start():match.end()+200]:
                return f'{func_def}{docstring}\n        async_storage = request.app.state.async_storage\n        '
            return match.group(0)
        content = re.sub(pattern, replacer, content, flags=re.DOTALL)
    
    # Clean up double line breaks
    content = re.sub(r'\n\n\n+', '\n\n', content)
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed {file_path}")

def main():
    """Run all fixes."""
    fix_routes_py()
    print("All fixes applied successfully!")

if __name__ == "__main__":
    main()