"""Unified storage implementation using asgiref for sync/async bridge.

This module provides a single storage interface that works in both
sync and async contexts, eliminating code duplication.
"""

import asyncio
from typing import Optional, Any
import redis.asyncio as redis_async
from asgiref.sync import sync_to_async, async_to_sync
from ..shared.logger import log_info, log_debug, log_error, log_warning


class UnifiedStorage:
    """Unified storage that bridges sync and async contexts.
    
    Architecture:
    - Single source of truth: AsyncRedisStorage
    - Automatic sync/async conversion using asgiref
    - Zero code duplication
    - Thread-safe Redis operations
    """
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._async_pool: Optional[redis_async.ConnectionPool] = None
        self._async_storage: Optional['AsyncRedisStorage'] = None
        self._initialized = False
        
    def initialize(self):
        """Synchronous initialization for legacy components."""
        if self._initialized:
            return
        
        log_info("Initializing UnifiedStorage (sync mode)", component="unified_storage")
        
        # Check if we're in an async context
        try:
            asyncio.get_running_loop()
            # We're in an async context, cannot use async_to_sync
            raise RuntimeError(
                "Cannot call synchronous initialize() from async context. "
                "Use 'await storage.initialize_async()' instead."
            )
        except RuntimeError as e:
            if "no running event loop" not in str(e).lower():
                # Re-raise if it's not the "no running loop" error
                raise
        
        # We're in a sync context, safe to use async_to_sync
        async_to_sync(self._initialize_async)()
        self._initialized = True
        
        log_info("UnifiedStorage initialized successfully (sync mode)", component="unified_storage")
        
    async def initialize_async(self):
        """Asynchronous initialization for async components."""
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"UnifiedStorage.initialize_async() called, _initialized={self._initialized}")
        if self._initialized:
            logger.warning("UnifiedStorage already initialized, skipping")
            log_debug("UnifiedStorage already initialized, skipping", component="unified_storage")
            return
            
        logger.info("Initializing UnifiedStorage (async mode)")
        log_info("Initializing UnifiedStorage (async mode)", component="unified_storage")
        
        await self._initialize_async()
        self._initialized = True
        
        log_info("UnifiedStorage initialized successfully (async mode)", component="unified_storage")
        
    async def _initialize_async(self):
        """Core initialization logic (async)."""
        import logging
        logger = logging.getLogger(__name__)
        logger.info("CRITICAL: _initialize_async() starting - this MUST initialize defaults")
        log_info("CRITICAL: _initialize_async() starting - this MUST initialize defaults", component="unified_storage")
        # Create connection pool using redis-py
        self._async_pool = redis_async.ConnectionPool.from_url(
            self.redis_url,
            decode_responses=True,
            max_connections=50,
            health_check_interval=30
        )
        
        # Initialize AsyncRedisStorage with the pool
        from ._async_redis_storage import AsyncRedisStorage
        self._async_storage = AsyncRedisStorage(self.redis_url)
        
        # Initialize the Redis client
        await self._async_storage.initialize()
        
        # CRITICAL: Initialize defaults (fixes OAuth bug)
        logger.info("About to initialize default proxies and routes")
        log_info("Initializing default proxies and routes", component="unified_storage")
        logger.info("Calling self._async_storage.initialize_default_proxies()")
        await self._async_storage.initialize_default_proxies()
        logger.info("Calling self._async_storage.initialize_default_routes()")
        await self._async_storage.initialize_default_routes()
        logger.info("Default proxies and routes initialization complete")
        log_info("Default proxies and routes initialized", component="unified_storage")
        
    def __getattr__(self, name: str) -> Any:
        """Smart method delegation with automatic sync/async conversion."""
        if not self._initialized:
            # Auto-initialize on first use
            log_warning(f"WARNING: Auto-initializing UnifiedStorage on first use of '{name}' - this may skip default initialization!", component="unified_storage")
            import traceback
            log_debug(f"Stack trace: {''.join(traceback.format_stack())}", component="unified_storage")
            self.initialize()
            
        # Get the attribute from async storage
        attr = getattr(self._async_storage, name)
        
        # Non-coroutine attributes pass through
        if not asyncio.iscoroutinefunction(attr):
            return attr
            
        # For sync-only access, always return sync version
        # This is determined by checking if method name ends with _sync
        if name.endswith('_sync'):
            # User explicitly wants sync version
            actual_name = name[:-5]  # Remove _sync suffix
            actual_attr = getattr(self._async_storage, actual_name)
            return async_to_sync(actual_attr)
            
        # Check execution context
        try:
            asyncio.get_running_loop()
            # In async context, return async method directly
            log_debug(f"Returning async method {name} for async context", component="unified_storage")
            return attr
        except RuntimeError:
            # In sync context, wrap with async_to_sync
            log_debug(f"Wrapping async method {name} for sync context", component="unified_storage")
            return async_to_sync(attr)
            
    @property
    def redis_client(self):
        """Get Redis client for direct access.
        
        Returns the underlying Redis client from AsyncRedisStorage.
        This is needed for components that need direct Redis access,
        like CertificateManager's scan operations.
        """
        if not self._initialized:
            log_warning("Accessing redis_client before initialization", component="unified_storage")
            self.initialize()
        
        if self._async_storage and hasattr(self._async_storage, 'redis_client'):
            return self._async_storage.redis_client
        else:
            log_error("Redis client not available", component="unified_storage")
            return None
    
    def get_sync_interface(self):
        """Get a sync-only interface that always returns sync methods.
        
        This is useful for components that are entirely synchronous and
        should never receive async methods even when in async context.
        
        Note: This cannot be used from within an async context as async_to_sync
        doesn't work when an event loop is already running.
        """
        # Check if we're in an async context
        try:
            asyncio.get_running_loop()
            # We're in an async context
            log_warning(
                "get_sync_interface() called from async context. "
                "Returning storage as-is, which will return async methods.",
                component="unified_storage"
            )
            # Can't use async_to_sync in async context, return self
            return self
        except RuntimeError:
            # Not in async context, safe to create sync interface
            pass
            
        class SyncInterface:
            def __init__(self, storage):
                self._storage = storage
                
            def __getattr__(self, name):
                attr = getattr(self._storage._async_storage, name)
                if asyncio.iscoroutinefunction(attr):
                    # Only use async_to_sync if not in async context
                    try:
                        asyncio.get_running_loop()
                        # In async context, can't use async_to_sync
                        raise RuntimeError(
                            f"Cannot use sync interface method '{name}' from async context. "
                            "Use await with the async version instead."
                        )
                    except RuntimeError as e:
                        if "no running event loop" not in str(e).lower():
                            raise
                    return async_to_sync(attr)
                return attr
                
        return SyncInterface(self)
            
    def close(self):
        """Synchronous cleanup."""
        if self._async_storage and self._async_pool:
            log_info("Closing UnifiedStorage (sync)", component="unified_storage")
            async_to_sync(self._cleanup)()
            
    async def close_async(self):
        """Asynchronous cleanup."""
        log_info("Closing UnifiedStorage (async)", component="unified_storage")
        await self._cleanup()
        
    async def _cleanup(self):
        """Core cleanup logic."""
        if self._async_storage:
            await self._async_storage.close()
        if self._async_pool:
            await self._async_pool.disconnect()
        log_info("UnifiedStorage cleanup complete", component="unified_storage")