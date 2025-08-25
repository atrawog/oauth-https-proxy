"""Main entry point for OAuth HTTPS Proxy."""

import asyncio
import os
import sys
from typing import Optional

from .shared.config import Config, get_config
from .shared.logger import log_debug, log_info, log_warning, log_error, log_trace
from .storage import RedisStorage
from .certmanager import CertificateManager, HTTPSServer, CertificateScheduler
from .proxy import ProxyHandler
# Delayed imports to prevent app creation at module load time
# These will be imported in the functions that need them

# Using unified async logger

# Global instances
manager: Optional[CertificateManager] = None
https_server: Optional[HTTPSServer] = None
scheduler: Optional[CertificateScheduler] = None
proxy_handler: Optional[ProxyHandler] = None


async def initialize_components(config: Config) -> tuple:
    """Initialize all system components with async architecture.
    
    Returns:
        Tuple of (storage, manager, scheduler, proxy_handler, async_components, https_server)
    """
    # Initialize storage with Redis URL
    redis_url = config.get_redis_url_with_password()
    storage = RedisStorage(redis_url)
    # Since we're in async context, must initialize async
    await storage.initialize_async()
    
    # Initialize async components
    from .api.async_init import init_async_components
    async_components = await init_async_components(redis_url)
    log_info("Async components initialized", component="main")
    
    # Logging is now handled by UnifiedAsyncLogger initialized in async_components
    log_info("Using UnifiedAsyncLogger for all logging", component="main")
    
    # Initialize certificate manager (sync for now, will be replaced by async)
    manager = CertificateManager(storage)
    
    # Initialize HTTPS server
    https_server = HTTPSServer(manager)
    await https_server.load_certificates()
    
    # Initialize scheduler
    scheduler = CertificateScheduler(manager)
    
    # Initialize proxy handler with async components
    # Note: UnifiedProxyHandler needs async storage and redis clients
    proxy_handler = ProxyHandler(
        async_components.async_storage,
        async_components.redis_clients
    )
    
    # Initialize default routes
    await storage.initialize_default_routes()
    
    # Initialize default proxies
    await storage.initialize_default_proxies()
    
    # Note: Flexible auth system is initialized directly in run_server()
    
    log_info("All components initialized successfully", component="main")
    
    return storage, manager, scheduler, proxy_handler, async_components, https_server


def create_asgi_app():
    """Create the FastAPI ASGI app for production deployment.
    
    This function creates a minimal FastAPI app that can be used with
    ASGI servers. The full initialization happens during the lifespan.
    
    Returns:
        FastAPI app instance
    """
    from contextlib import asynccontextmanager
    from fastapi import FastAPI
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Manage application lifecycle."""
        # Get configuration
        config = get_config()
        
        # Setup logging

        log_info("Starting OAuth HTTPS Proxy (ASGI mode)", component="main")
        
        # Initialize all components
        storage, manager, scheduler, proxy_handler, async_components, https_server = await initialize_components(config)
        
        # Create base API app
        # Note: We don't use create_api_app here to avoid circular dependencies
        # Instead we'll attach everything directly
        
        # Store core components in app state
        app.state.storage = storage
        app.state.cert_manager = manager
        app.state.scheduler = scheduler
        app.state.https_server = https_server
        app.state.proxy_handler = proxy_handler
        
        # Attach async components
        app.state.async_components = async_components
        app.state.async_storage = async_components.async_storage
        app.state.unified_logger = async_components.unified_logger
        app.state.metrics_processor = async_components.metrics_processor
        app.state.alert_manager = async_components.alert_manager
        app.state.docker_manager = async_components.docker_manager
        app.state.cert_manager = async_components.cert_manager
        
        # Use AsyncLogStorage for request logging (already initialized in async_components)
        # The middleware will access it via app.state.async_storage
        log_info("Using AsyncLogStorage for request logging via Redis Streams", component="main")
        
        # Auth system removed - OAuth only authentication at proxy layer
        log_info("✓ OAuth-only authentication (auth handled at proxy layer)", component="main")
        
        # Register all routers using unified registry
        log_info("Registering all routers with Unified Router Registry...", component="main")
        try:
            from .api.routers.registry import register_all_routers
            register_all_routers(app)
            log_info("✓ All routers registered successfully", component="main")
        except Exception as e:
            log_error(f"✗ Router registration failed: {e}", component="main")
            raise
        
        # Start scheduler
        scheduler.start()
        
        # For ASGI mode, we don't start the full server here
        log_info("ASGI app initialized and ready", component="main")
        
        yield
        
        # Shutdown
        log_info("Shutting down OAuth HTTPS Proxy...", component="main")
        scheduler.stop()
        if proxy_handler:
            await proxy_handler.close()
        await async_components.shutdown()
    
    # Create the FastAPI app with lifespan
    from .api.server import create_api_app
    
    # Get config for initial app creation
    config = get_config()
    redis_url = config.get_redis_url_with_password()
    storage = RedisStorage(redis_url)
    temp_manager = CertificateManager(storage)
    temp_scheduler = CertificateScheduler(temp_manager)
    
    app = create_api_app(storage, temp_manager, temp_scheduler)
    app.router.lifespan_context = lifespan
    
    return app


async def run_server(config: Config) -> None:
    """Run OAuth HTTPS Proxy with simplified Docker-aware startup."""
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Python logging: run_server() started")
    
    # Step 1: Initialize core components
    log_info("=" * 60, component="main")
    log_info("OAUTH HTTPS PROXY STARTUP", component="main")
    log_info("=" * 60, component="main")
    log_info("Step 1/5: Initializing core components", component="main")
    logger.info("Python logging: Step 1/5 - Initializing core components")
    storage, manager, scheduler, proxy_handler, async_components, https_server = \
        await initialize_components(config)
    logger.info("Python logging: Step 1/5 complete")
    
    # Step 2: Create FastAPI application
    log_info("Step 2/5: Creating FastAPI application", component="main")
    logger.info("Python logging: Step 2/5 - Creating FastAPI application")
    from .api.server import create_api_app
    app = create_api_app(storage, manager, scheduler)
    logger.info("Python logging: Step 2/5 complete")
    
    # Attach only essential components
    app.state.async_components = async_components
    app.state.async_storage = async_components.async_storage
    app.state.unified_logger = async_components.unified_logger
    app.state.storage = storage  # Legacy support
    
    # Step 3: Register all routers
    log_info("Step 3/5: Registering API routers", component="main")
    logger.info("Python logging: Step 3/5 - Registering API routers")
    try:
        from .api.routers.registry import register_all_routers
        register_all_routers(app)
        log_info("✓ All routers registered successfully", component="main")
        logger.info("Python logging: Step 3/5 complete")
    except Exception as e:
        logger.error(f"Python logging: Router registration failed - {e}", exc_info=True)
        log_error(f"✗ Router registration failed: {e}", component="main")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}", component="main")
        raise RuntimeError(f"Failed to register routers: {e}")
    
    scheduler.start()
    
    try:
        # Step 4: Start API on SINGLE port with Docker awareness
        log_info("Step 4/5: Starting API on port 9000 (internal only)", component="main")
        logger.info("Python logging: Step 4/5 - Starting API on port 9000")
        from hypercorn.asyncio import serve
        from hypercorn.config import Config as HypercornConfig
        
        api_config = HypercornConfig()
        
        # Bind correctly for Docker networking
        if os.getenv('RUNNING_IN_DOCKER'):
            api_config.bind = ["0.0.0.0:9000"]  # Accept connections from other containers
            log_info("API binding to 0.0.0.0:9000 (Docker mode)", component="main")
        else:
            api_config.bind = ["127.0.0.1:9000"]  # Local development
            log_info("API binding to 127.0.0.1:9000 (local mode)", component="main")
        
        api_config.loglevel = config.LOG_LEVEL.upper()
        api_task = asyncio.create_task(serve(app, api_config))
        logger.info("Python logging: Step 4/5 complete - API task created")
        
        # Removed redundant ports 9001 and 10001 - API runs on single port 9000
        
        # Step 5: Start dispatcher with proxy instances
        log_info("Step 5/5: Starting dispatcher with proxy instances", component="main")
        logger.info("Python logging: Step 5/5 - Starting dispatcher with proxy instances")
        try:
            logger.info("Python logging: Importing UnifiedMultiInstanceServer")
            from .dispatcher import UnifiedMultiInstanceServer
            logger.info("Python logging: Creating UnifiedMultiInstanceServer")
            unified_server = UnifiedMultiInstanceServer(
                https_server_instance=https_server,
                app=None,  # No app needed - proxy instances only
                host=config.SERVER_HOST,
                async_components=async_components,
                storage=storage
            )
            log_info("✅ UnifiedMultiInstanceServer created successfully", component="main")
            logger.info("Python logging: Step 5/5 complete - UnifiedMultiInstanceServer created")
        except Exception as e:
            logger.error(f"Python logging: UnifiedMultiInstanceServer creation failed - {e}", exc_info=True)
            log_error(f"CRITICAL FAILURE: UnifiedMultiInstanceServer creation failed: {e}", component="main")
            import traceback
            log_error(f"Full traceback: {traceback.format_exc()}", component="main")
            raise RuntimeError(f"Cannot continue without UnifiedMultiInstanceServer: {e}")
        
        # Run everything
        log_info("All components initialized, starting services...", component="main")
        logger.info("Python logging: Creating unified_task for dispatcher")
        unified_task = asyncio.create_task(unified_server.run())
        logger.info("Python logging: Starting asyncio.gather for api_task and unified_task")
        await asyncio.gather(
            api_task,
            unified_task
            # NO return_exceptions - we want failures to be LOUD!
        )
        logger.info("Python logging: asyncio.gather completed")
    finally:
        scheduler.stop()
        if proxy_handler:
            await proxy_handler.close()
        
        # Shutdown async components
        await async_components.shutdown()
        log_info("Async components shut down", component="main")


def main() -> None:
    """Main entry point for CLI execution.
    
    This is used when running the server directly via `python run.py` or
    `python -m src.main`. It initializes everything and runs the full server.
    """
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    try:
        # Get and validate configuration
        config = get_config()
        logger.info(f"Python logging: Config loaded - HTTP={config.HTTP_PORT}, HTTPS={config.HTTPS_PORT}")
        
        # Setup logging (Redis-based)
        log_info("=" * 60, component="main")
        log_info("OAUTH HTTPS PROXY STARTING (CLI MODE)", component="main")
        log_info("=" * 60, component="main")
        log_info("Starting OAuth HTTPS Proxy via run.py...", component="main")
        log_info(f"Configuration loaded: HTTP={config.HTTP_PORT}, HTTPS={config.HTTPS_PORT}", component="main")
        
        # Run the server
        logger.info("Python logging: Starting asyncio.run(run_server(config))")
        asyncio.run(run_server(config))
        logger.info("Python logging: asyncio.run completed")
        
    except KeyboardInterrupt:
        logger.info("Python logging: Shutting down (interrupted)")
        log_info("Shutting down OAuth HTTPS Proxy (interrupted)", component="main")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Python logging: Failed to start - {e}", exc_info=True)
        # Don't use async log_error here since we may not have an event loop
        print(f"ERROR: Failed to start OAuth HTTPS Proxy: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()