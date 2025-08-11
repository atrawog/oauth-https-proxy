#!/usr/bin/env python3
"""Remove ALL sync code and use ONLY async implementations."""

import os
import re
from pathlib import Path

os.chdir('/home/atrawog/AI/atrawog/mcp-http-proxy')

print("REMOVING ALL SYNC CODE - ASYNC ONLY!")

# Fix 1: services/__init__.py - Remove sync manager completely
print("\n1. Fixing services/__init__.py...")
with open('src/api/routers/v1/services/__init__.py', 'r') as f:
    content = f.read()

content = content.replace(
    'def create_services_router(async_storage, docker_manager, https_server=None):',
    'def create_services_router(async_storage, docker_manager=None, https_server=None):'
)

# Update docker router creation to not require docker_manager
content = re.sub(
    r'docker_router = create_docker_router\(async_storage, docker_manager\)',
    'docker_router = create_docker_router(async_storage)',
    content
)

# Update ports router
content = re.sub(
    r'ports_router = create_ports_router\(async_storage, docker_manager\)',
    'ports_router = create_ports_router(async_storage)',
    content
)

# Update proxy router
content = re.sub(
    r'proxy_router = create_proxy_integration_router\(async_storage, docker_manager\)',
    'proxy_router = create_proxy_integration_router(async_storage)',
    content
)

# Update cleanup router
content = re.sub(
    r'cleanup_router = create_cleanup_router\(async_storage, docker_manager\)',
    'cleanup_router = create_cleanup_router(async_storage)',
    content
)

with open('src/api/routers/v1/services/__init__.py', 'w') as f:
    f.write(content)
print("✓ Fixed services/__init__.py")

# Fix 2: services/docker.py - Remove ALL sync references
print("\n2. Fixing services/docker.py...")
with open('src/api/routers/v1/services/docker.py', 'r') as f:
    content = f.read()

# Change signature to not accept docker_manager_sync at all
content = re.sub(
    r'def create_docker_router\(storage, docker_manager_sync=None\) -> APIRouter:',
    'def create_docker_router(async_storage) -> APIRouter:',
    content
)

# Update docstring
content = content.replace(
    '        storage: Redis storage instance (legacy)',
    '        async_storage: Async Redis storage instance'
)
content = content.replace(
    '        docker_manager_sync: Ignored - always use async from app.state',
    ''
)

# Fix get_docker_manager to ONLY use async
new_get_docker_manager = '''    async def get_docker_manager(request: Request):
        """Get async Docker manager from app state ONLY."""
        # ONLY use async components - NO SYNC FALLBACKS!
        if hasattr(request.app.state, 'docker_manager'):
            return request.app.state.docker_manager
        
        if hasattr(request.app.state, 'async_components'):
            if request.app.state.async_components and hasattr(request.app.state.async_components, 'docker_manager'):
                return request.app.state.async_components.docker_manager
        
        # No manager? Service unavailable
        raise HTTPException(503, "Docker service not initialized")'''

content = re.sub(
    r'    async def get_docker_manager\(request: Request\):.*?raise HTTPException\(503, "Docker service unavailable"\)',
    new_get_docker_manager,
    content,
    flags=re.DOTALL
)

with open('src/api/routers/v1/services/docker.py', 'w') as f:
    f.write(content)
print("✓ Fixed services/docker.py")

# Fix 3: services/external.py - Ensure async only
print("\n3. Fixing services/external.py...")
with open('src/api/routers/v1/services/external.py', 'r') as f:
    content = f.read()

# Ensure we're using async_storage everywhere
content = re.sub(
    r'def create_external_router\(async_storage\) -> APIRouter:',
    'def create_external_router(async_storage) -> APIRouter:',
    content
)

# Make sure all functions get async_storage from request.app.state
content = re.sub(
    r'(\s+)# Get async async_storage if available\n\s+async_storage = request\.app\.state\.async_storage',
    r'\1# Get async storage from app state (REQUIRED)\n\1async_storage = request.app.state.async_storage',
    content
)

with open('src/api/routers/v1/services/external.py', 'w') as f:
    f.write(content)
print("✓ Fixed services/external.py")

# Fix 4: services/ports.py - Remove docker_manager parameter
print("\n4. Fixing services/ports.py...")
ports_file = 'src/api/routers/v1/services/ports.py'
if os.path.exists(ports_file):
    with open(ports_file, 'r') as f:
        content = f.read()
    
    content = re.sub(
        r'def create_ports_router\(async_storage, docker_manager\) -> APIRouter:',
        'def create_ports_router(async_storage) -> APIRouter:',
        content
    )
    
    with open(ports_file, 'w') as f:
        f.write(content)
    print("✓ Fixed services/ports.py")

# Fix 5: services/proxy_integration.py
print("\n5. Fixing services/proxy_integration.py...")
proxy_file = 'src/api/routers/v1/services/proxy_integration.py'
if os.path.exists(proxy_file):
    with open(proxy_file, 'r') as f:
        content = f.read()
    
    content = re.sub(
        r'def create_proxy_integration_router\(async_storage, docker_manager\) -> APIRouter:',
        'def create_proxy_integration_router(async_storage) -> APIRouter:',
        content
    )
    
    with open(proxy_file, 'w') as f:
        f.write(content)
    print("✓ Fixed services/proxy_integration.py")

# Fix 6: services/cleanup.py
print("\n6. Fixing services/cleanup.py...")
cleanup_file = 'src/api/routers/v1/services/cleanup.py'
if os.path.exists(cleanup_file):
    with open(cleanup_file, 'r') as f:
        content = f.read()
    
    content = re.sub(
        r'def create_cleanup_router\(async_storage, docker_manager\) -> APIRouter:',
        'def create_cleanup_router(async_storage) -> APIRouter:',
        content
    )
    
    with open(cleanup_file, 'w') as f:
        f.write(content)
    print("✓ Fixed services/cleanup.py")

# Fix 7: Update v1/__init__.py to not pass docker_manager
print("\n7. Fixing v1/__init__.py...")
with open('src/api/routers/v1/__init__.py', 'r') as f:
    content = f.read()

# Remove docker_manager references
content = re.sub(
    r'docker_manager = app\.state\.docker_manager if hasattr\(app\.state, \'docker_manager\'\) else None',
    '# Docker manager comes from async_components, not passed directly',
    content
)

# Fix services router creation
content = re.sub(
    r'services\.create_services_router\(async_storage, docker_manager\)',
    'services.create_services_router(async_storage)',
    content
)

# Remove the if docker_manager check
content = re.sub(
    r'if docker_manager:\s*v1_router\.include_router\(',
    'v1_router.include_router(',
    content
)

with open('src/api/routers/v1/__init__.py', 'w') as f:
    f.write(content)
print("✓ Fixed v1/__init__.py")

# Fix 8: Update main services.py to not pass docker_manager
print("\n8. Fixing main services.py...")
with open('src/api/routers/v1/services.py', 'r') as f:
    content = f.read()

# Already fixed earlier, but ensure it's correct
content = '''"""Service management API endpoints (Docker and external services).

This module redirects to the modular service management structure.
"""

from .services import create_services_router


def create_router(storage):
    """Create the services API router (Docker and external).
    
    Uses ONLY async components from app.state - no sync fallbacks!
    
    Args:
        storage: Async Redis storage instance
    
    Returns:
        APIRouter with all service endpoints
    """
    # Everything is async - managers come from request.app.state
    return create_services_router(storage)
'''

with open('src/api/routers/v1/services.py', 'w') as f:
    f.write(content)
print("✓ Fixed main services.py")

print("\n✅ ALL SYNC CODE REMOVED! Everything is now fully async!")
print("No more sync fallbacks, no more sync managers - pure async architecture!")