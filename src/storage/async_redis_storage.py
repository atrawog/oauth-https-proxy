"""DEPRECATED: Use UnifiedStorage instead.

This module exists only for backward compatibility during migration.
Direct use of AsyncRedisStorage is deprecated and will be removed in a future version.

Migration guide:
1. Replace: from ..storage.async_redis_storage import AsyncRedisStorage
   With: from ..storage import UnifiedStorage
   
2. UnifiedStorage works in both sync and async contexts automatically
3. No other code changes needed - the API is identical
"""

import warnings
from .unified_storage import UnifiedStorage

class AsyncRedisStorage(UnifiedStorage):
    """DEPRECATED: Use UnifiedStorage instead.
    
    This class is a compatibility wrapper that will be removed in a future version.
    Please migrate to UnifiedStorage which provides the same functionality
    and works in both sync and async contexts.
    """
    
    def __init__(self, redis_url: str):
        warnings.warn(
            "Direct use of AsyncRedisStorage is deprecated. "
            "Use UnifiedStorage from src.storage instead. "
            "UnifiedStorage works in both sync and async contexts automatically.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(redis_url)
        
    async def initialize(self):
        """Initialize for compatibility with old AsyncRedisStorage usage."""
        await self.initialize_async()

# For compatibility - export the deprecated class
__all__ = ['AsyncRedisStorage']