"""Legacy RedisStorage - redirects to UnifiedStorage.

This module provides backward compatibility by redirecting to UnifiedStorage.
All business logic is now in AsyncRedisStorage, accessed through UnifiedStorage.
"""

from .unified_storage import UnifiedStorage as RedisStorage

__all__ = ['RedisStorage']