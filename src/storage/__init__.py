"""Storage module with unified architecture and compatibility shims.

The storage layer provides a unified interface that works in both
sync and async contexts, eliminating code duplication.
"""

from .unified_storage import UnifiedStorage
from ..shared.logger import log_info


# Compatibility shim for old RedisStorage
class RedisStorage(UnifiedStorage):
    """Drop-in replacement for legacy RedisStorage.
    
    This is a thin wrapper around UnifiedStorage that maintains
    backward compatibility with sync-only code.
    
    Note: If used from async context, you must call await storage.initialize_async()
    after creation instead of relying on auto-initialization.
    """
    
    def __init__(self, redis_url: str):
        super().__init__(redis_url)
        log_info("RedisStorage compatibility shim initialized (using UnifiedStorage)", component="storage")
        
        # Check if we're in an async context
        import asyncio
        try:
            asyncio.get_running_loop()
            # We're in an async context, don't auto-initialize
            log_info("RedisStorage created in async context - call await storage.initialize_async()", component="storage")
        except RuntimeError:
            # We're in a sync context, auto-initialize for backward compatibility
            self.initialize()
        
    # All methods inherited from UnifiedStorage work automatically


# Compatibility shim for old AsyncRedisStorage  
class AsyncRedisStorage(UnifiedStorage):
    """Drop-in replacement for legacy AsyncRedisStorage.
    
    This is a thin wrapper around UnifiedStorage that maintains
    backward compatibility with async-only code.
    """
    
    def __init__(self, redis_url: str):
        super().__init__(redis_url)
        log_info("AsyncRedisStorage compatibility shim initialized (using UnifiedStorage)", component="storage")
    
    async def initialize(self):
        """Async initialization for compatibility."""
        await self.initialize_async()
        
    # All methods inherited from UnifiedStorage work automatically


# Export all three for flexibility
__all__ = ['UnifiedStorage', 'RedisStorage', 'AsyncRedisStorage']