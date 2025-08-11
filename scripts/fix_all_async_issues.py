#!/usr/bin/env python3
"""Fix ALL remaining async issues in the codebase."""

import os
import re

def fix_docker_router():
    """Fix docker.py to use async components consistently."""
    file_path = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/docker.py"
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Fix get_docker_manager to be more robust
    new_get_docker_manager = '''    async def get_docker_manager(request: Request):
        """Get async Docker manager from app state ONLY."""
        # Try direct app.state first
        if hasattr(request.app.state, 'docker_manager'):
            manager = request.app.state.docker_manager
            if manager is not None:
                return manager
        
        # Try async_components
        if hasattr(request.app.state, 'async_components'):
            components = request.app.state.async_components
            if components and hasattr(components, 'docker_manager'):
                manager = components.docker_manager
                if manager is not None:
                    return manager
        
        # No manager available
        raise HTTPException(503, "Docker service not initialized")'''
    
    # Replace the get_docker_manager function
    pattern = r'    async def get_docker_manager\(request: Request\):.*?raise HTTPException\(503, "Docker service not initialized"\)'
    content = re.sub(pattern, new_get_docker_manager, content, flags=re.DOTALL)
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed docker.py")

def fix_external_router():
    """Fix external.py to use async storage consistently."""
    file_path = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/external.py"
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Ensure all async_storage accesses are from request.app.state
    # Remove any inconsistent comments
    content = re.sub(
        r'            # Get async storage from app state \(REQUIRED\)\n\n            async_storage = request\.app\.state\.async_storage',
        '            # Get async storage from app state\n            async_storage = request.app.state.async_storage',
        content
    )
    
    content = re.sub(
        r'            # Get async storage from app state \(REQUIRED\)\n\n            \n            async_storage = request\.app\.state\.async_storage',
        '            # Get async storage from app state\n            async_storage = request.app.state.async_storage',
        content
    )
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed external.py")

def fix_services_init():
    """Remove docker_manager parameter from services/__init__.py."""
    file_path = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/__init__.py"
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Remove docker_manager and https_server parameters
    content = re.sub(
        r'def create_services_router\(async_storage, docker_manager=None, https_server=None\):',
        'def create_services_router(async_storage):',
        content
    )
    
    # Update docstring
    content = re.sub(
        r'    Args:\n        async_storage: Redis async_storage instance\n        docker_manager: Docker manager instance\n        https_server: HTTPS server instance \(optional, can be obtained from request\.app\.state\)',
        '    Args:\n        async_storage: Redis async_storage instance',
        content
    )
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed services/__init__.py")

def fix_ports_router():
    """Fix ports.py to use async components consistently."""
    file_path = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/ports.py"
    
    if not os.path.exists(file_path):
        print(f"⚠ ports.py not found, skipping")
        return
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Ensure all endpoints use Request parameter and get managers from app.state
    if 'async def ' in content and 'Request' not in content:
        content = re.sub(r'from fastapi import', 'from fastapi import Request,', content)
    
    # Add get_docker_manager if it references docker_manager
    if 'docker_manager' in content and 'get_docker_manager' not in content:
        # Add the helper function after the router creation
        helper = '''
    async def get_docker_manager(request: Request):
        """Get async Docker manager from app state."""
        if hasattr(request.app.state, 'docker_manager'):
            manager = request.app.state.docker_manager
            if manager is not None:
                return manager
        
        if hasattr(request.app.state, 'async_components'):
            components = request.app.state.async_components
            if components and hasattr(components, 'docker_manager'):
                manager = components.docker_manager
                if manager is not None:
                    return manager
        
        return None  # Docker manager is optional for ports
'''
        content = re.sub(r'(router = APIRouter\(\))', r'\1' + helper, content)
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed ports.py")

def fix_proxy_integration_router():
    """Fix proxy_integration.py to use async components consistently."""
    file_path = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/proxy_integration.py"
    
    if not os.path.exists(file_path):
        print(f"⚠ proxy_integration.py not found, skipping")
        return
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Ensure all endpoints use Request parameter
    if 'async def ' in content and 'Request' not in content:
        content = re.sub(r'from fastapi import', 'from fastapi import Request,', content)
    
    # Ensure async_storage is gotten from request.app.state
    content = re.sub(
        r'async_storage\.',
        'request.app.state.async_storage.',
        content
    )
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed proxy_integration.py")

def fix_cleanup_router():
    """Fix cleanup.py to use async components consistently."""
    file_path = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/cleanup.py"
    
    if not os.path.exists(file_path):
        print(f"⚠ cleanup.py not found, skipping")
        return
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Ensure all endpoints use Request parameter
    if 'async def ' in content and 'Request' not in content:
        content = re.sub(r'from fastapi import', 'from fastapi import Request,', content)
    
    # Add get_docker_manager if it references docker operations
    if 'docker' in content.lower() and 'get_docker_manager' not in content:
        helper = '''
    async def get_docker_manager(request: Request):
        """Get async Docker manager from app state."""
        if hasattr(request.app.state, 'docker_manager'):
            manager = request.app.state.docker_manager
            if manager is not None:
                return manager
        
        if hasattr(request.app.state, 'async_components'):
            components = request.app.state.async_components
            if components and hasattr(components, 'docker_manager'):
                manager = components.docker_manager
                if manager is not None:
                    return manager
        
        return None  # Docker manager is optional
'''
        content = re.sub(r'(router = APIRouter\(\))', r'\1' + helper, content)
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed cleanup.py")

def main():
    """Fix all async issues."""
    print("Fixing ALL remaining async issues...")
    
    fix_docker_router()
    fix_external_router()
    fix_services_init()
    fix_ports_router()
    fix_proxy_integration_router()
    fix_cleanup_router()
    
    print("\n✅ All async issues fixed!")
    print("\nNext steps:")
    print("1. Rebuild the API service: just rebuild api")
    print("2. Run comprehensive tests: ./scripts/comprehensive_command_test.sh")

if __name__ == "__main__":
    main()