"""Integration module to wire async components into FastAPI application.

This module provides integration points for the async Redis Streams
architecture with the existing FastAPI application.
"""

import logging
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, Depends
from contextlib import asynccontextmanager

from ..orchestrator.main_orchestrator import MainOrchestrator
from ..storage.redis_clients import RedisClients
from ..storage.async_redis_storage import AsyncRedisStorage
from ..docker.async_manager import AsyncDockerManager
from ..certmanager.async_manager import AsyncCertificateManager
from ..proxy.unified_handler import UnifiedProxyHandler
from ..ports.async_manager import AsyncPortManager
from ..shared.unified_logger import UnifiedAsyncLogger

logger = logging.getLogger(__name__)


class AppIntegration:
    """Integrates async components with FastAPI application."""
    
    _instance: Optional['AppIntegration'] = None
    _orchestrator: Optional[MainOrchestrator] = None
    
    def __new__(cls):
        """Ensure singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    async def initialize(cls) -> 'AppIntegration':
        """Initialize the integration with orchestrator.
        
        Returns:
            Initialized integration instance
        """
        instance = cls()
        
        if cls._orchestrator is None:
            logger.info("Initializing app integration with orchestrator...")
            cls._orchestrator = MainOrchestrator()
            await cls._orchestrator.initialize()
            await cls._orchestrator.start()
            logger.info("App integration initialized successfully")
        
        return instance
    
    @classmethod
    async def shutdown(cls) -> None:
        """Shutdown the integration and orchestrator."""
        if cls._orchestrator:
            logger.info("Shutting down app integration...")
            await cls._orchestrator.stop()
            cls._orchestrator = None
            cls._instance = None
            logger.info("App integration shutdown complete")
    
    @property
    def orchestrator(self) -> MainOrchestrator:
        """Get the orchestrator instance."""
        if self._orchestrator is None:
            raise RuntimeError("Integration not initialized")
        return self._orchestrator
    
    @property
    def redis_clients(self) -> RedisClients:
        """Get Redis clients."""
        return self.orchestrator.redis_clients
    
    @property
    def async_storage(self) -> AsyncRedisStorage:
        """Get async storage."""
        return self.orchestrator.async_storage
    
    @property
    def docker_manager(self) -> AsyncDockerManager:
        """Get Docker manager."""
        return self.orchestrator.docker_manager
    
    @property
    def cert_manager(self) -> AsyncCertificateManager:
        """Get certificate manager."""
        return self.orchestrator.cert_manager
    
    @property
    def proxy_handler(self) -> UnifiedProxyHandler:
        """Get proxy handler."""
        return self.orchestrator.proxy_handler
    
    @property
    def port_manager(self) -> AsyncPortManager:
        """Get port manager."""
        return self.orchestrator.port_manager
    
    @property
    def logger(self) -> UnifiedAsyncLogger:
        """Get unified logger."""
        return self.orchestrator.logger


# Global integration instance
_integration: Optional[AppIntegration] = None


async def get_integration() -> AppIntegration:
    """Dependency to get the integration instance.
    
    Returns:
        Integration instance
    """
    global _integration
    if _integration is None:
        _integration = await AppIntegration.initialize()
    return _integration


async def get_async_storage(
    integration: AppIntegration = Depends(get_integration)
) -> AsyncRedisStorage:
    """Dependency to get async storage.
    
    Args:
        integration: App integration instance
        
    Returns:
        Async storage instance
    """
    return integration.async_storage


async def get_docker_manager(
    integration: AppIntegration = Depends(get_integration)
) -> AsyncDockerManager:
    """Dependency to get Docker manager.
    
    Args:
        integration: App integration instance
        
    Returns:
        Docker manager instance
    """
    return integration.docker_manager


async def get_cert_manager(
    integration: AppIntegration = Depends(get_integration)
) -> AsyncCertificateManager:
    """Dependency to get certificate manager.
    
    Args:
        integration: App integration instance
        
    Returns:
        Certificate manager instance
    """
    return integration.cert_manager


async def get_proxy_handler(
    integration: AppIntegration = Depends(get_integration)
) -> UnifiedProxyHandler:
    """Dependency to get proxy handler.
    
    Args:
        integration: App integration instance
        
    Returns:
        Proxy handler instance
    """
    return integration.proxy_handler


async def get_port_manager(
    integration: AppIntegration = Depends(get_integration)
) -> AsyncPortManager:
    """Dependency to get port manager.
    
    Args:
        integration: App integration instance
        
    Returns:
        Port manager instance
    """
    return integration.port_manager


async def get_unified_logger(
    integration: AppIntegration = Depends(get_integration)
) -> UnifiedAsyncLogger:
    """Dependency to get unified logger.
    
    Args:
        integration: App integration instance
        
    Returns:
        Unified logger instance
    """
    return integration.logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context manager with async components.
    
    Args:
        app: FastAPI application instance
    """
    # Startup
    logger.info("Starting FastAPI with async Redis Streams architecture...")
    
    try:
        # Initialize integration
        integration = await AppIntegration.initialize()
        
        # Store in app state for easy access
        app.state.integration = integration
        app.state.redis_clients = integration.redis_clients
        app.state.async_storage = integration.async_storage
        app.state.docker_manager = integration.docker_manager
        app.state.cert_manager = integration.cert_manager
        app.state.proxy_handler = integration.proxy_handler
        app.state.port_manager = integration.port_manager
        app.state.logger = integration.logger
        
        logger.info("FastAPI startup complete with async components")
        
        # Yield control to app
        yield
        
    finally:
        # Shutdown
        logger.info("Shutting down FastAPI with async components...")
        await AppIntegration.shutdown()
        logger.info("FastAPI shutdown complete")


def create_app_with_integration() -> FastAPI:
    """Create FastAPI app with async integration.
    
    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="MCP HTTP Proxy with Async Redis Streams",
        lifespan=lifespan
    )
    
    return app


async def add_trace_middleware(request: Request, call_next):
    """Middleware to add trace IDs to all requests.
    
    Args:
        request: FastAPI request
        call_next: Next middleware/handler
        
    Returns:
        Response with trace headers
    """
    # Get integration
    if hasattr(request.app.state, "logger"):
        logger = request.app.state.logger
        
        # Start trace for the request
        trace_id = logger.start_trace(
            "http_request",
            method=request.method,
            path=str(request.url.path),
            client=request.client.host if request.client else "unknown"
        )
        
        # Store in request state
        request.state.trace_id = trace_id
        
        try:
            # Process request
            response = await call_next(request)
            
            # Add trace ID to response headers
            response.headers["X-Trace-Id"] = trace_id
            
            # End trace
            await logger.end_trace(trace_id, "success", status_code=response.status_code)
            
            return response
            
        except Exception as e:
            # Log error and end trace
            await logger.error(
                f"Request failed: {str(e)}",
                trace_id=trace_id,
                error_type=type(e).__name__
            )
            await logger.end_trace(trace_id, "error", error=str(e))
            raise
    else:
        # Fallback if logger not available
        return await call_next(request)


def integrate_with_existing_app(app: FastAPI) -> None:
    """Integrate async components with existing FastAPI app.
    
    Args:
        app: Existing FastAPI application
    """
    # Add middleware
    app.middleware("http")(add_trace_middleware)
    
    # Add status endpoint
    @app.get("/api/v1/orchestrator/status")
    async def get_orchestrator_status(
        integration: AppIntegration = Depends(get_integration)
    ) -> Dict[str, Any]:
        """Get orchestrator and component status."""
        return await integration.orchestrator.get_status()
    
    # Add metrics endpoint
    @app.get("/api/v1/orchestrator/metrics")
    async def get_metrics(
        integration: AppIntegration = Depends(get_integration)
    ) -> Dict[str, Any]:
        """Get current metrics from processors."""
        metrics_processor = integration.orchestrator.metrics_processor
        if metrics_processor:
            return await metrics_processor.get_current_metrics()
        return {"error": "Metrics processor not available"}
    
    # Add alerts endpoint
    @app.get("/api/v1/orchestrator/alerts")
    async def get_alerts(
        integration: AppIntegration = Depends(get_integration)
    ) -> Dict[str, Any]:
        """Get current alerts."""
        alert_manager = integration.orchestrator.alert_manager
        if alert_manager:
            return await alert_manager.get_alert_summary()
        return {"error": "Alert manager not available"}
    
    logger.info("Async integration added to existing app")