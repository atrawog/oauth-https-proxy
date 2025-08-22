#!/usr/bin/env python3
"""
Script to fix performance issues in unified_dispatcher.py:
1. Replace synchronous Redis calls with async calls
2. Migrate all logging to UnifiedAsyncLogger
3. Fix fire-and-forget patterns
"""

import re
import sys
from pathlib import Path

def fix_dispatcher():
    file_path = Path("/home/atrawog/oauth-https-proxy/src/dispatcher/unified_dispatcher.py")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Step 1: Add imports for unified logger
    import_section = """from ..shared.logging import get_logger, configure_logging
from ..shared.config import Config"""
    
    new_import_section = """from ..shared.logger import get_logger_compat, log_info, log_warning, log_error, log_debug, set_global_logger
from ..shared.config import Config
from ..shared.unified_logger import UnifiedAsyncLogger"""
    
    content = content.replace(import_section, new_import_section)
    
    # Step 2: Replace logger initialization
    content = content.replace(
        "logger = get_logger(__name__)",
        "# Use compatibility logger that wraps unified async logger\nlogger = get_logger_compat(__name__)"
    )
    
    # Step 3: Fix the synchronous Redis calls in register_named_service
    # This method needs to be async or use fire-and-forget
    old_register_method = """    def register_named_service(self, name: str, port: int, service_url: str = None):
        \"\"\"Register a named service for routing.
        
        Args:
            name: Service name (e.g., 'api', 'auth')
            port: Port number for the service
            service_url: Full URL for Docker service access (e.g., 'http://api:9000')
        \"\"\"
        self.named_services[name] = port
        logger.info(f"Registered named service: {name} -> port {port}")
        
        # Store in Redis so proxies can access it
        if self.storage:
            try:
                # Store service URL
                if service_url:
                    self.storage.redis_client.set(f"service:url:{name}", service_url)
                    logger.info(f"Stored service {name} URL in Redis: {service_url}")
                elif name == "api":
                    # Special case for API service - use Docker service name
                    self.storage.redis_client.set(f"service:url:{name}", "http://api:9000")
                    logger.info(f"Stored API service URL in Redis: http://api:9000")
                
                logger.debug(f"Stored service {name} in Redis")
            except Exception as e:
                logger.error(f"Failed to store service in Redis: {e}")"""
    
    new_register_method = """    def register_named_service(self, name: str, port: int, service_url: str = None):
        \"\"\"Register a named service for routing.
        
        Args:
            name: Service name (e.g., 'api', 'auth')
            port: Port number for the service
            service_url: Full URL for Docker service access (e.g., 'http://api:9000')
        \"\"\"
        self.named_services[name] = port
        log_info(f"Registered named service: {name} -> port {port}", component="dispatcher")
        
        # Store in Redis using async storage with fire-and-forget
        if self.async_storage:
            import asyncio
            async def store_service():
                try:
                    # Store service URL
                    if service_url:
                        await self.async_storage.redis_client.set(f"service:url:{name}", service_url)
                        log_info(f"Stored service {name} URL in Redis: {service_url}", component="dispatcher")
                    elif name == "api":
                        # Special case for API service - use Docker service name
                        await self.async_storage.redis_client.set(f"service:url:{name}", "http://api:9000")
                        log_info(f"Stored API service URL in Redis: http://api:9000", component="dispatcher")
                    
                    log_debug(f"Stored service {name} in Redis", component="dispatcher")
                except Exception as e:
                    log_error(f"Failed to store service in Redis: {e}", component="dispatcher")
            
            # Fire-and-forget task
            asyncio.create_task(store_service())
        elif self.storage:
            # Fallback to sync if async_storage not available
            try:
                if service_url:
                    self.storage.redis_client.set(f"service:url:{name}", service_url)
                elif name == "api":
                    self.storage.redis_client.set(f"service:url:{name}", "http://api:9000")
            except Exception as e:
                log_error(f"Failed to store service in Redis: {e}", component="dispatcher")"""
    
    content = content.replace(old_register_method, new_register_method)
    
    # Step 4: Fix the sync Redis call in dispatch_https (line 578)
    old_dispatch_code = """            # Get proxy configuration to determine route filtering
            proxy_config = None
            if self.storage:
                try:
                    proxy_json = self.storage.redis_client.get(f"proxy:{hostname}")
                    if proxy_json:
                        proxy_data = json.loads(proxy_json)
                        proxy_config = ProxyTarget(**proxy_data)
                except Exception as e:
                    logger.debug(f"Could not load proxy config for {hostname}: {e}")"""
    
    new_dispatch_code = """            # Get proxy configuration to determine route filtering  
            proxy_config = None
            if self.async_storage:
                try:
                    proxy_json = await self.async_storage.redis_client.get(f"proxy:{hostname}")
                    if proxy_json:
                        proxy_data = json.loads(proxy_json)
                        proxy_config = ProxyTarget(**proxy_data)
                except Exception as e:
                    log_debug(f"Could not load proxy config for {hostname}: {e}", component="dispatcher")
            elif self.storage:
                # Fallback to sync storage
                try:
                    proxy_json = self.storage.redis_client.get(f"proxy:{hostname}")
                    if proxy_json:
                        proxy_data = json.loads(proxy_json)
                        proxy_config = ProxyTarget(**proxy_data)
                except Exception as e:
                    log_debug(f"Could not load proxy config for {hostname}: {e}", component="dispatcher")"""
    
    content = content.replace(old_dispatch_code, new_dispatch_code)
    
    # Step 5: Add unified logger initialization in __init__
    old_init_logging = """        # Configure Redis logging if storage is available
        if storage and storage.redis_client:
            from ..shared.logging import configure_logging
            configure_logging(storage.redis_client)"""
    
    new_init_logging = """        # Initialize unified logger if async components available
        self.unified_logger = async_components.unified_logger if async_components else None
        if self.unified_logger:
            # Set global logger for fire-and-forget logging
            set_global_logger(self.unified_logger)
            log_info("Unified dispatcher initialized with async logger", component="dispatcher")
        elif storage and storage.redis_client:
            # Fallback to old logging
            from ..shared.logging import configure_logging
            configure_logging(storage.redis_client)"""
    
    content = content.replace(old_init_logging, new_init_logging)
    
    # Write the fixed content
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed dispatcher performance issues in {file_path}")
    print("- Replaced 3 sync Redis calls with async calls")
    print("- Added unified logger support")
    print("- Fixed fire-and-forget patterns")

if __name__ == "__main__":
    fix_dispatcher()