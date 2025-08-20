"""Async component initialization for the API server.

This module provides initialization of the async Redis Streams architecture
components for use within the existing FastAPI application.
"""

import logging
from typing import Optional
from fastapi import FastAPI

from ..storage.redis_clients import RedisClients, initialize_redis_clients
from ..storage.async_redis_storage import AsyncRedisStorage
from ..shared.unified_logger import UnifiedAsyncLogger
from ..consumers.metrics_processor import MetricsProcessor
from ..consumers.alert_manager import AlertManager
from ..docker.async_manager import AsyncDockerManager
from ..certmanager.async_manager import AsyncCertificateManager

logger = logging.getLogger(__name__)


class AsyncComponents:
    """Container for async architecture components."""
    
    def __init__(self):
        self.redis_clients: Optional[RedisClients] = None
        self.async_storage: Optional[AsyncRedisStorage] = None
        self.unified_logger: Optional[UnifiedAsyncLogger] = None
        self.metrics_processor: Optional[MetricsProcessor] = None
        self.alert_manager: Optional[AlertManager] = None
        self.docker_manager: Optional[AsyncDockerManager] = None
        self.cert_manager: Optional[AsyncCertificateManager] = None
        self.initialized = False
    
    async def initialize(self, redis_url: str):
        """Initialize all async components.
        
        Args:
            redis_url: Redis connection URL
        """
        if self.initialized:
            logger.warning("Async components already initialized")
            return
        
        try:
            logger.info("Initializing async Redis Streams components...")
            
            # Initialize Redis clients
            # Note: initialize_redis_clients doesn't take parameters, it uses env var
            self.redis_clients = RedisClients(redis_url)
            await self.redis_clients.initialize()
            logger.info("Redis clients initialized")
            
            # Initialize async storage
            self.async_storage = AsyncRedisStorage(redis_url)
            await self.async_storage.initialize()
            logger.info("Async storage initialized")
            
            # Initialize unified logger
            self.unified_logger = UnifiedAsyncLogger(self.redis_clients)
            self.unified_logger.set_component("api_server")
            logger.info("Unified logger initialized")
            
            # Initialize async managers
            self.docker_manager = AsyncDockerManager(self.async_storage, self.redis_clients)
            logger.info("Async Docker manager initialized")
            
            self.cert_manager = AsyncCertificateManager(self.async_storage, self.redis_clients)
            logger.info("Async Certificate manager initialized")
            
            # Initialize consumers
            self.metrics_processor = MetricsProcessor(self.redis_clients.stream_redis)
            self.alert_manager = AlertManager(self.redis_clients.stream_redis)
            
            # Start consumers
            await self.metrics_processor.start()
            await self.alert_manager.start()
            logger.info("Stream consumers started")
            
            self.initialized = True
            logger.info("Async components initialization complete")
            
            # Log initialization event
            await self.unified_logger.event(
                "async_components_initialized",
                {
                    "redis_clients": "initialized",
                    "async_storage": "initialized",
                    "unified_logger": "initialized",
                    "docker_manager": "initialized",
                    "cert_manager": "initialized",
                    "metrics_processor": "started",
                    "alert_manager": "started"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize async components: {e}")
            raise
    
    async def shutdown(self):
        """Shutdown all async components."""
        if not self.initialized:
            return
        
        logger.info("Shutting down async components...")
        
        try:
            # Stop consumers
            if self.metrics_processor:
                await self.metrics_processor.stop()
                logger.info("Metrics processor stopped")
            
            if self.alert_manager:
                await self.alert_manager.stop()
                logger.info("Alert manager stopped")
            
            # Flush logger
            if self.unified_logger:
                await self.unified_logger.flush()
                logger.info("Logger flushed")
            
            # Close storage
            if self.async_storage:
                await self.async_storage.close()
                logger.info("Async storage closed")
            
            # Close Redis clients
            if self.redis_clients:
                await self.redis_clients.close()
                logger.info("Redis clients closed")
            
            self.initialized = False
            logger.info("Async components shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during async components shutdown: {e}")


# Global instance
_async_components: Optional[AsyncComponents] = None


def get_async_components() -> Optional[AsyncComponents]:
    """Get the global async components instance.
    
    Returns:
        AsyncComponents instance if initialized, None otherwise
    """
    return _async_components


async def init_async_components(redis_url: str) -> AsyncComponents:
    """Initialize and return async components.
    
    Args:
        redis_url: Redis connection URL
        
    Returns:
        Initialized AsyncComponents instance
    """
    global _async_components
    
    if _async_components is None:
        _async_components = AsyncComponents()
        await _async_components.initialize(redis_url)
    
    return _async_components


# DEPRECATED: attach_to_app has been removed
# Use the unified router registry directly via register_all_routers()
# Component attachment is done in main.py and app.py directly