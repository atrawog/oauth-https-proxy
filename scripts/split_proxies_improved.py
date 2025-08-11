#!/usr/bin/env python3
"""Improved script to split proxies router with precise extraction."""

import re
from pathlib import Path


def extract_function_block(content, function_name, indent_level=1):
    """Extract a complete function block including decorators."""
    lines = content.split('\n')
    result = []
    indent = '    ' * indent_level
    
    # Find the decorator before the function
    in_function = False
    function_started = False
    brace_count = 0
    
    for i, line in enumerate(lines):
        # Look for decorator
        if f'@router.' in line and not function_started:
            # Check if next async def matches our function
            for j in range(i, min(i+5, len(lines))):
                if f'async def {function_name}(' in lines[j]:
                    function_started = True
                    result.append(line)
                    break
        elif function_started and not in_function:
            result.append(line)
            if f'async def {function_name}(' in line:
                in_function = True
                brace_count = line.count('(') - line.count(')')
        elif in_function:
            result.append(line)
            brace_count += line.count('(') - line.count(')')
            
            # Check if we're at the end of the function
            # A function ends when we hit another decorator or reach proper indentation
            if len(line) > 0:
                line_indent = len(line) - len(line.lstrip())
                # If we're back at function level and not in a multi-line statement
                if line_indent <= 4 and brace_count <= 0:
                    # Check if this is a new function or decorator
                    if '@router.' in line or 'async def' in line or 'def ' in line:
                        # We've hit the next function, stop
                        result.pop()  # Remove the line we just added
                        break
    
    return '\n'.join(result)


def create_async_core_module():
    """Create core.py with async patterns built-in."""
    
    original_path = Path('src/api/routers/v1/proxies.py.bak')
    with open(original_path, 'r') as f:
        content = f.read()
    
    # Extract specific functions
    create_func = extract_function_block(content, 'create_proxy_target')
    list_func = extract_function_block(content, 'list_proxy_targets')
    list_formatted_func = extract_function_block(content, 'list_proxy_targets_formatted')
    get_func = extract_function_block(content, 'get_proxy_target')
    update_func = extract_function_block(content, 'update_proxy_target')
    delete_func = extract_function_block(content, 'delete_proxy_target')
    
    module = f'''"""Core proxy CRUD operations with async support.

This module handles basic Create, Read, Update, Delete operations for proxy targets.
All operations use async patterns with fallback to sync for backward compatibility.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query, Request
from fastapi.responses import PlainTextResponse
import csv
import io
from tabulate import tabulate

from ...auth import require_auth, require_auth_header, get_current_token_info
from ....proxy.models import ProxyTarget, ProxyTargetRequest, ProxyTargetUpdate
from ....certmanager.models import CertificateRequest, Certificate

logger = logging.getLogger(__name__)


def create_core_router(storage, cert_manager):
    """Create router for core proxy CRUD operations.
    
    All endpoints use async patterns with Request parameter to access async components.
    
    Args:
        storage: Redis storage instance (legacy, for backward compatibility)
        cert_manager: Certificate manager instance (legacy, for backward compatibility)
    
    Returns:
        APIRouter with core proxy endpoints
    """
    router = APIRouter()
    
    {create_func}
    
    {list_func}
    
    {list_formatted_func}
    
    {get_func}
    
    {update_func}
    
    {delete_func}
    
    return router
'''
    
    return module


def create_async_auth_module():
    """Create auth.py with async patterns."""
    
    original_path = Path('src/api/routers/v1/proxies.py.bak')
    with open(original_path, 'r') as f:
        content = f.read()
    
    configure_func = extract_function_block(content, 'configure_proxy_auth')
    remove_func = extract_function_block(content, 'remove_proxy_auth')
    get_func = extract_function_block(content, 'get_proxy_auth_config')
    
    module = f'''"""Proxy authentication configuration with async support.

This module handles OAuth authentication configuration for proxy targets.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request

from ...auth import require_proxy_owner, require_auth_header
from ....proxy.models import ProxyAuthConfig

logger = logging.getLogger(__name__)


def create_auth_router(storage):
    """Create router for proxy authentication configuration.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        storage: Redis storage instance (legacy)
    
    Returns:
        APIRouter with proxy auth endpoints
    """
    router = APIRouter()
    
    {configure_func}
    
    {remove_func}
    
    {get_func}
    
    return router
'''
    
    return module


def create_async_routes_module():
    """Create routes.py with async patterns."""
    
    original_path = Path('src/api/routers/v1/proxies.py.bak')
    with open(original_path, 'r') as f:
        content = f.read()
    
    get_func = extract_function_block(content, 'get_proxy_routes')
    update_func = extract_function_block(content, 'update_proxy_routes')
    enable_func = extract_function_block(content, 'enable_proxy_route')
    disable_func = extract_function_block(content, 'disable_proxy_route')
    
    module = f'''"""Proxy route management with async support.

This module handles route configuration for proxy targets.
"""

import logging
from typing import List
from fastapi import APIRouter, HTTPException, Depends, Request

from ...auth import require_proxy_owner, require_auth_header
from ....proxy.models import ProxyRoutesConfig

logger = logging.getLogger(__name__)


def create_routes_router(storage):
    """Create router for proxy route management.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        storage: Redis storage instance (legacy)
    
    Returns:
        APIRouter with proxy route endpoints
    """
    router = APIRouter()
    
    {get_func}
    
    {update_func}
    
    {enable_func}
    
    {disable_func}
    
    return router
'''
    
    return module


def create_async_resources_module():
    """Create resources.py with async patterns."""
    
    original_path = Path('src/api/routers/v1/proxies.py.bak')
    with open(original_path, 'r') as f:
        content = f.read()
    
    configure_func = extract_function_block(content, 'configure_proxy_resource')
    get_func = extract_function_block(content, 'get_proxy_resource_config')
    remove_func = extract_function_block(content, 'remove_proxy_resource')
    
    module = f'''"""Proxy MCP resource configuration with async support.

This module handles MCP (Model Context Protocol) resource metadata configuration.
"""

import logging
from fastapi import APIRouter, HTTPException, Depends, Request

from ...auth import require_proxy_owner, require_auth_header
from ....proxy.models import ProxyResourceConfig

logger = logging.getLogger(__name__)


def create_resources_router(storage):
    """Create router for proxy resource configuration.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        storage: Redis storage instance (legacy)
    
    Returns:
        APIRouter with proxy resource endpoints
    """
    router = APIRouter()
    
    {configure_func}
    
    {get_func}
    
    {remove_func}
    
    return router
'''
    
    return module


def main():
    """Main function to create properly split modules."""
    
    module_dir = Path('src/api/routers/v1/proxies')
    
    # Create each module with async patterns
    modules = {
        'core.py': create_async_core_module(),
        'auth.py': create_async_auth_module(),
        'routes.py': create_async_routes_module(),
        'resources.py': create_async_resources_module()
    }
    
    for filename, content in modules.items():
        module_path = module_dir / filename
        with open(module_path, 'w') as f:
            f.write(content)
        
        # Count lines for reporting
        lines = len(content.split('\n'))
        print(f"✅ Created {filename}: {lines} lines")
    
    print("\n✨ Proxies router successfully split with async patterns!")
    print("\nModule sizes are now manageable and include async support.")


if __name__ == "__main__":
    main()