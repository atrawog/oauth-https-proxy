#!/usr/bin/env python3
"""Script to complete async migration of proxies router."""

import re
import sys

def migrate_proxies_router(file_path):
    """Migrate proxies router to async patterns."""
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Track if we made changes
    original = content
    
    # Pattern 1: Add Request parameter to route handlers that don't have it
    patterns = [
        # Routes that need Request parameter
        (r'(@router\.\w+\([^)]+\)\s+async def \w+)\(\s*hostname: str,',
         r'\1(\n        req: Request,\n        hostname: str,'),
        
        (r'(@router\.\w+\([^)]+\)\s+async def \w+)\(\s*format: str',
         r'\1(\n        req: Request,\n        format: str'),
    ]
    
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    
    # Pattern 2: Replace storage calls with async equivalents
    replacements = [
        # Get proxy target
        ('target = storage.get_proxy_target(hostname)',
         '''# Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        if async_storage:
            target = await async_storage.get_proxy_target(hostname)
        else:
            target = storage.get_proxy_target(hostname)'''),
        
        # Store proxy target
        ('storage.store_proxy_target(hostname, target)',
         '''if async_storage:
            await async_storage.store_proxy_target(hostname, target)
        else:
            storage.store_proxy_target(hostname, target)'''),
            
        # Delete proxy target
        ('storage.delete_proxy_target(hostname)',
         '''if async_storage:
            await async_storage.delete_proxy_target(hostname)
        else:
            storage.delete_proxy_target(hostname)'''),
            
        # List proxy targets
        ('targets = storage.list_proxy_targets()',
         '''# Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        if async_storage:
            targets = await async_storage.list_proxy_targets()
        else:
            targets = storage.list_proxy_targets()'''),
    ]
    
    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
    
    # Write back if changed
    if content != original:
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"✅ Migrated {file_path}")
        return True
    else:
        print(f"ℹ️ No changes needed for {file_path}")
        return False

if __name__ == "__main__":
    file_path = "src/api/routers/v1/proxies.py"
    if migrate_proxies_router(file_path):
        print("Migration completed successfully")
    else:
        print("No migration needed")