#!/usr/bin/env python3
"""Script to split the monolithic proxies.py router into modular components."""

import os
import re
from pathlib import Path


def extract_imports_and_helpers(content):
    """Extract imports and helper functions from the content."""
    lines = content.split('\n')
    imports = []
    in_function = False
    function_lines = []
    
    for line in lines:
        # Collect imports
        if line.startswith('import ') or line.startswith('from '):
            imports.append(line)
        # Break when we hit the router creation
        elif 'def create_router' in line:
            break
        # Collect any helper functions or constants
        elif line and not line.startswith('#'):
            function_lines.append(line)
    
    return '\n'.join(imports), '\n'.join(function_lines)


def extract_endpoints(content, endpoint_names):
    """Extract specific endpoint functions from content."""
    endpoints = {}
    lines = content.split('\n')
    
    for endpoint_name in endpoint_names:
        # Find the start of the endpoint
        pattern = rf'@router\.\w+.*?\n\s*async def {endpoint_name}\('
        match = re.search(pattern, content, re.DOTALL)
        
        if match:
            start_idx = match.start()
            # Find the end (next @router or end of function)
            rest_content = content[start_idx:]
            
            # Find the next @router or the end
            next_router = re.search(r'\n    @router\.', rest_content)
            if next_router:
                endpoint_content = rest_content[:next_router.start()]
            else:
                # This is the last endpoint
                endpoint_content = rest_content
            
            endpoints[endpoint_name] = endpoint_content.rstrip()
    
    return endpoints


def create_core_module(original_content):
    """Create the core.py module with basic CRUD operations."""
    
    core_endpoints = [
        'create_proxy_target',
        'list_proxy_targets', 
        'list_proxy_targets_formatted',
        'get_proxy_target',
        'update_proxy_target',
        'delete_proxy_target'
    ]
    
    imports, helpers = extract_imports_and_helpers(original_content)
    endpoints = extract_endpoints(original_content, core_endpoints)
    
    module_content = f'''"""Core proxy CRUD operations.

This module handles basic Create, Read, Update, Delete operations for proxy targets.
Split from the monolithic proxies.py for better maintainability.
"""

{imports}

logger = logging.getLogger(__name__)


def create_core_router(storage, cert_manager):
    """Create router for core proxy CRUD operations.
    
    Args:
        storage: Redis storage instance (legacy)
        cert_manager: Certificate manager instance (legacy)
    
    Returns:
        APIRouter with core proxy endpoints
    """
    router = APIRouter()
    
'''
    
    # Add each endpoint
    for endpoint_name in core_endpoints:
        if endpoint_name in endpoints:
            # Indent the endpoint content properly
            endpoint_lines = endpoints[endpoint_name].split('\n')
            indented = '\n'.join('    ' + line if line else '' for line in endpoint_lines)
            module_content += indented + '\n\n'
    
    module_content += '    return router\n'
    
    return module_content


def create_auth_module(original_content):
    """Create the auth.py module with authentication configuration."""
    
    auth_endpoints = [
        'configure_proxy_auth',
        'remove_proxy_auth',
        'get_proxy_auth_config'
    ]
    
    endpoints = extract_endpoints(original_content, auth_endpoints)
    
    module_content = f'''"""Proxy authentication configuration endpoints.

This module handles OAuth authentication configuration for proxy targets.
"""

import logging
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, Request

from ...auth import require_auth, require_auth_header, require_proxy_owner
from ....proxy.models import ProxyAuthConfig

logger = logging.getLogger(__name__)


def create_auth_router(storage):
    """Create router for proxy authentication configuration.
    
    Args:
        storage: Redis storage instance (legacy)
    
    Returns:
        APIRouter with proxy auth endpoints
    """
    router = APIRouter()
    
'''
    
    # Add each endpoint
    for endpoint_name in auth_endpoints:
        if endpoint_name in endpoints:
            endpoint_lines = endpoints[endpoint_name].split('\n')
            indented = '\n'.join('    ' + line if line else '' for line in endpoint_lines)
            module_content += indented + '\n\n'
    
    module_content += '    return router\n'
    
    return module_content


def create_routes_module(original_content):
    """Create the routes.py module with route management."""
    
    route_endpoints = [
        'get_proxy_routes',
        'update_proxy_routes',
        'enable_proxy_route',
        'disable_proxy_route'
    ]
    
    endpoints = extract_endpoints(original_content, route_endpoints)
    
    module_content = f'''"""Proxy route management endpoints.

This module handles route configuration for proxy targets.
"""

import logging
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, Request

from ...auth import require_proxy_owner
from ....proxy.models import ProxyRoutesConfig

logger = logging.getLogger(__name__)


def create_routes_router(storage):
    """Create router for proxy route management.
    
    Args:
        storage: Redis storage instance (legacy)
    
    Returns:
        APIRouter with proxy route endpoints
    """
    router = APIRouter()
    
'''
    
    # Add each endpoint
    for endpoint_name in route_endpoints:
        if endpoint_name in endpoints:
            endpoint_lines = endpoints[endpoint_name].split('\n')
            indented = '\n'.join('    ' + line if line else '' for line in endpoint_lines)
            module_content += indented + '\n\n'
    
    module_content += '    return router\n'
    
    return module_content


def create_resources_module(original_content):
    """Create the resources.py module with MCP resource configuration."""
    
    resource_endpoints = [
        'configure_proxy_resource',
        'get_proxy_resource_config',
        'remove_proxy_resource'
    ]
    
    endpoints = extract_endpoints(original_content, resource_endpoints)
    
    module_content = f'''"""Proxy MCP resource configuration endpoints.

This module handles MCP (Model Context Protocol) resource metadata configuration.
"""

import logging
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, Request

from ...auth import require_proxy_owner
from ....proxy.models import ProxyResourceConfig

logger = logging.getLogger(__name__)


def create_resources_router(storage):
    """Create router for proxy resource configuration.
    
    Args:
        storage: Redis storage instance (legacy)
    
    Returns:
        APIRouter with proxy resource endpoints
    """
    router = APIRouter()
    
'''
    
    # Add each endpoint
    for endpoint_name in resource_endpoints:
        if endpoint_name in endpoints:
            endpoint_lines = endpoints[endpoint_name].split('\n')
            indented = '\n'.join('    ' + line if line else '' for line in endpoint_lines)
            module_content += indented + '\n\n'
    
    module_content += '    return router\n'
    
    return module_content


def main():
    """Main function to split the proxies router."""
    
    # Read the original file
    original_path = Path('src/api/routers/v1/proxies.py')
    with open(original_path, 'r') as f:
        original_content = f.read()
    
    # Create the module directory
    module_dir = Path('src/api/routers/v1/proxies')
    module_dir.mkdir(exist_ok=True)
    
    # Create each module
    modules = {
        'core.py': create_core_module(original_content),
        'auth.py': create_auth_module(original_content),
        'routes.py': create_routes_module(original_content),
        'resources.py': create_resources_module(original_content)
    }
    
    for filename, content in modules.items():
        module_path = module_dir / filename
        with open(module_path, 'w') as f:
            f.write(content)
        print(f"✅ Created {module_path}")
    
    # Rename original file to .bak
    backup_path = original_path.with_suffix('.py.bak')
    original_path.rename(backup_path)
    print(f"📦 Original file backed up to {backup_path}")
    
    print("\n✨ Proxies router successfully split into modular structure!")
    print("\nNext steps:")
    print("1. Review the generated modules for correctness")
    print("2. Add async migration to each module")
    print("3. Test the refactored structure")


if __name__ == "__main__":
    main()