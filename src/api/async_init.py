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


def attach_to_app(app: FastAPI, components: AsyncComponents):
    """Attach async components to FastAPI app state.
    
    Args:
        app: FastAPI application
        components: Initialized async components
    """
    app.state.async_components = components
    app.state.async_storage = components.async_storage
    app.state.unified_logger = components.unified_logger
    
    # Initialize request logger
    from src.logging.request_logger import RequestLogger
    app.state.request_logger = RequestLogger(components.async_storage.redis_client if components.async_storage else None)
    
    # Set global request logger
    from src.shared.logging import set_request_logger
    set_request_logger(app.state.request_logger)
    app.state.metrics_processor = components.metrics_processor
    app.state.alert_manager = components.alert_manager
    app.state.docker_manager = components.docker_manager
    app.state.cert_manager = components.cert_manager
    
    # Initialize flexible auth service
    from src.auth import FlexibleAuthService
    from src.auth.defaults import initialize_auth_system
    import asyncio
    
    # Create auth service with storage and OAuth components
    oauth_components = getattr(app.state, 'oauth_components', None)
    app.state.auth_service = FlexibleAuthService(
        storage=components.async_storage,
        oauth_components=oauth_components
    )
    
    # Initialize auth service asynchronously
    async def init_auth():
        await app.state.auth_service.initialize()
        # Load default configurations
        await initialize_auth_system(
            components.async_storage,
            load_defaults=True,
            migrate=True
        )
        logger.info("Flexible auth system initialized with defaults")
    
    # Run initialization in background
    asyncio.create_task(init_auth())
    
    logger.info("Async components attached to FastAPI app")
    
    # Now create and attach the v1 router with async_storage available
    try:
        from .routers.v1 import create_v1_router
        
        # Create v1 router and mount at root for clean URLs
        v1_router = create_v1_router(app)
        
        # Mount at root path for clean, consistent URLs
        # Note: OAuth endpoints like /token are singular without trailing slash
        # while API endpoints like /tokens/ are plural with trailing slash, so no conflict
        app.include_router(v1_router, prefix="")
        logger.info("API v1 router included at root path /")
        
    except ImportError as e:
        logger.error(f"Failed to import v1 router: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
    except Exception as e:
        logger.error(f"Failed to include v1 router: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")