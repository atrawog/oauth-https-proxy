"""Async log level manager for dynamic configuration.

This module provides pure async, fire-and-forget log level management
without any local caching - all state is managed by Redis.
"""

import asyncio
import logging
from typing import Optional, Dict, Any
from enum import IntEnum

class LogLevel(IntEnum):
    """Log levels with numeric values for comparison."""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    
    @classmethod
    def from_string(cls, level: str) -> 'LogLevel':
        """Convert string level to enum."""
        try:
            return cls[level.upper()]
        except KeyError:
            return cls.INFO


class AsyncLogLevelManager:
    """Pure async log level manager - no caching, all Redis."""
    
    def __init__(self, redis_client):
        """Initialize with Redis client.
        
        Args:
            redis_client: Async Redis client for level lookups
        """
        self.redis = redis_client
        
    async def should_log(self, level: str, component: str) -> bool:
        """Check if a log should be written based on configured levels.
        
        Pure async operation - no caching, direct Redis lookup.
        
        Args:
            level: Log level of the message (TRACE, DEBUG, INFO, etc.)
            component: Component name
            
        Returns:
            True if the log should be written
        """
        try:
            # Convert level string to numeric value
            msg_level = LogLevel.from_string(level)
            
            # Get effective level from Redis (component > global > default)
            effective_level = await self.get_effective_level(component)
            
            # Compare numeric values
            return msg_level >= effective_level
            
        except Exception:
            # On any error, default to logging (fail open)
            return True
    
    async def get_effective_level(self, component: str) -> LogLevel:
        """Get the effective log level for a component.
        
        Checks component-specific level first, then global, then default.
        
        Args:
            component: Component name
            
        Returns:
            Effective LogLevel enum value
        """
        try:
            # Try component-specific level first
            comp_level = await self.redis.get(f"log:level:component:{component}")
            if comp_level:
                return LogLevel.from_string(comp_level.decode() if isinstance(comp_level, bytes) else comp_level)
            
            # Fall back to global level
            global_level = await self.redis.get("log:level:global")
            if global_level:
                return LogLevel.from_string(global_level.decode() if isinstance(global_level, bytes) else global_level)
            
            # Default to INFO
            return LogLevel.INFO
            
        except Exception:
            # On Redis error, default to INFO
            return LogLevel.INFO
    
    async def set_level(self, level: str, component: Optional[str] = None) -> None:
        """Set log level for global or specific component.
        
        Args:
            level: Log level to set (TRACE, DEBUG, INFO, etc.)
            component: Optional component name (None for global)
        """
        # Validate level
        try:
            LogLevel.from_string(level)
        except KeyError:
            raise ValueError(f"Invalid log level: {level}")
        
        if component:
            await self.redis.set(f"log:level:component:{component}", level.upper())
        else:
            await self.redis.set("log:level:global", level.upper())
    
    async def get_all_levels(self) -> Dict[str, str]:
        """Get all configured log levels.
        
        Returns:
            Dict with global and component levels
        """
        result = {}
        
        # Get global level
        global_level = await self.redis.get("log:level:global")
        if global_level:
            result["global"] = global_level.decode() if isinstance(global_level, bytes) else global_level
        else:
            result["global"] = "INFO"
        
        # Get all component levels
        result["components"] = {}
        cursor = 0
        while True:
            cursor, keys = await self.redis.scan(
                cursor, 
                match="log:level:component:*",
                count=100
            )
            
            for key in keys:
                key_str = key.decode() if isinstance(key, bytes) else key
                component = key_str.replace("log:level:component:", "")
                level = await self.redis.get(key)
                if level:
                    result["components"][component] = level.decode() if isinstance(level, bytes) else level
            
            if cursor == 0:
                break
        
        return result
    
    async def reset_level(self, component: Optional[str] = None) -> None:
        """Reset log level to default.
        
        Args:
            component: Component to reset (None for global)
        """
        if component:
            await self.redis.delete(f"log:level:component:{component}")
        else:
            await self.redis.delete("log:level:global")
    
    def should_log_async(self, level: str, component: str) -> asyncio.Task:
        """Fire-and-forget check if log should be written.
        
        This returns a Task that can be awaited if needed, but is
        typically just fired and forgotten.
        
        Args:
            level: Log level of the message
            component: Component name
            
        Returns:
            Async task that resolves to bool
        """
        return asyncio.create_task(self.should_log(level, component))