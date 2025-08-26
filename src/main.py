"""Main entry point for OAuth HTTPS Proxy."""

import asyncio
import os
import sys
from typing import Optional

from .shared.config import Config, get_config
from .shared.logger import log_debug, log_info, log_warning, log_error, log_trace
from .shared.dual_logger import create_dual_logger, set_redis_logger_for_component
from .shared.python_logger_config import setup_python_logging
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

# Create dual logger for main component
dual_logger = create_dual_logger('main')

async def initialize_components(config: Config) -> tuple:
    """Initialize all system components with async architecture.
    
    Returns:
        Tuple of (storage, manager, scheduler, proxy_handler, async_components, https_server)
    """
    # Initialize storage with Redis URL
    redis_url = config.get_redis_url_with_password()
    dual_logger.info(f"Creating RedisStorage with URL pattern: redis://:****@{redis_url.split('@')[-1] if '@' in redis_url else 'redis:6379'}")
    storage = RedisStorage(redis_url)
    dual_logger.info("RedisStorage instance created")
    # Since we're in async context, must initialize async
    dual_logger.info("Calling storage.initialize_async()")
    await storage.initialize_async()
    dual_logger.info("storage.initialize_async() completed")
    
    # Initialize async components with shared storage
    from .api.async_init import init_async_components
    async_components = await init_async_components(redis_url, storage)
    dual_logger.info("Async components initialized with shared storage")
    
    # Set Redis logger for dual logger now that async components are ready
    if async_components and async_components.unified_logger:
        # Create a dedicated logger instance for main
        from .shared.unified_logger import UnifiedAsyncLogger
        main_redis_logger = UnifiedAsyncLogger(async_components.redis_clients, component="main")
        set_redis_logger_for_component('main', main_redis_logger)
        dual_logger.info("Dual logging enabled for main component")
    
    dual_logger.info("Using UnifiedAsyncLogger for all logging")
    
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
    dual_logger.info("Calling storage.initialize_default_routes()")
    await storage.initialize_default_routes()
    dual_logger.info("storage.initialize_default_routes() completed")
    
    # Initialize default proxies
    dual_logger.info("Calling storage.initialize_default_proxies()")
    await storage.initialize_default_proxies()
    dual_logger.info("storage.initialize_default_proxies() completed")
    
    # Note: Flexible auth system is initialized directly in run_server()
    
    dual_logger.info("All components initialized successfully")
    
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
        
        # Setup Python logging
        setup_python_logging()
        
        dual_logger.info("Starting OAuth HTTPS Proxy (ASGI mode)")
        
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
        dual_logger.info("Using AsyncLogStorage for request logging via Redis Streams")
        
        # Auth system removed - OAuth only authentication at proxy layer
        dual_logger.info("✓ OAuth-only authentication (auth handled at proxy layer)")
        
        # Register all routers using unified registry
        dual_logger.info("Registering all routers with Unified Router Registry...")
        try:
            from .api.routers.registry import register_all_routers
            register_all_routers(app)
            dual_logger.info("✓ All routers registered successfully")
        except Exception as e:
            dual_logger.error(f"✗ Router registration failed: {e}")
            raise
        
        # Start scheduler
        scheduler.start()
        
        # For ASGI mode, we don't start the full server here
        dual_logger.info("ASGI app initialized and ready")
        
        yield
        
        # Shutdown
        dual_logger.info("Shutting down OAuth HTTPS Proxy...")
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
    
    # Setup Python logging at the beginning
    setup_python_logging()
    
    # Step 1: Initialize core components
    dual_logger.info("=" * 60)
    dual_logger.info("OAUTH HTTPS PROXY STARTUP")
    dual_logger.info("=" * 60)
    dual_logger.info("Step 1/5: Initializing core components")
    storage, manager, scheduler, proxy_handler, async_components, https_server = \
        await initialize_components(config)
    
    # Step 2: Create FastAPI application
    dual_logger.info("Step 2/5: Creating FastAPI application")
    from .api.server import create_api_app
    app = create_api_app(storage, manager, scheduler)
    
    # Attach only essential components
    app.state.async_components = async_components
    app.state.async_storage = async_components.async_storage
    app.state.unified_logger = async_components.unified_logger
    app.state.storage = storage  # Legacy support
    
    # Step 3: Register all routers
    dual_logger.info("Step 3/5: Registering API routers")
    try:
        from .api.routers.registry import register_all_routers
        # register_all_routers may return a wrapper for MCP
        wrapped_app = register_all_routers(app)
        dual_logger.info("✓ All routers registered successfully")
    except Exception as e:
        dual_logger.error(f"✗ Router registration failed: {e}")
        import traceback
        dual_logger.error(f"Traceback: {traceback.format_exc()}")
        raise RuntimeError(f"Failed to register routers: {e}")
    
    scheduler.start()
    
    try:
        # Step 4: Start API on SINGLE port with Docker awareness
        dual_logger.info("Step 4/5: Starting API on port 9000 (internal only)")
        from hypercorn.asyncio import serve
        from hypercorn.config import Config as HypercornConfig
        
        api_config = HypercornConfig()
        
        # Bind correctly for Docker networking
        if os.getenv('RUNNING_IN_DOCKER'):
            api_config.bind = ["0.0.0.0:9000"]  # Accept connections from other containers
            dual_logger.info("API binding to 0.0.0.0:9000 (Docker mode)")
        else:
            api_config.bind = ["127.0.0.1:9000"]  # Local development
            dual_logger.info("API binding to 127.0.0.1:9000 (local mode)")
        
        api_config.loglevel = config.LOG_LEVEL.upper()
        # Serve the wrapped app (may include MCP wrapper)
        api_task = asyncio.create_task(serve(wrapped_app, api_config))
        
        # Removed redundant ports 9001 and 10001 - API runs on single port 9000
        
        # Step 5: Start dispatcher with proxy instances
        dual_logger.info("Step 5/5: Starting dispatcher with proxy instances")
        try:
            from .dispatcher import UnifiedMultiInstanceServer
            unified_server = UnifiedMultiInstanceServer(
                https_server_instance=https_server,
                app=None,  # No app needed - proxy instances only
                host=config.SERVER_HOST,
                async_components=async_components,
                storage=storage
            )
            dual_logger.info("✅ UnifiedMultiInstanceServer created successfully")
        except Exception as e:
            dual_logger.error(f"CRITICAL FAILURE: UnifiedMultiInstanceServer creation failed: {e}")
            import traceback
            dual_logger.error(f"Full traceback: {traceback.format_exc()}")
            raise RuntimeError(f"Cannot continue without UnifiedMultiInstanceServer: {e}")
        
        # Run everything
        dual_logger.info("All components initialized, starting services...")
        unified_task = asyncio.create_task(unified_server.run())
        await asyncio.gather(
            api_task,
            unified_task
            # NO return_exceptions - we want failures to be LOUD!
        )
    finally:
        scheduler.stop()
        if proxy_handler:
            await proxy_handler.close()
        
        # Shutdown async components
        await async_components.shutdown()
        dual_logger.info("Async components shut down")


def main() -> None:
    """Main entry point for CLI execution.
    
    This is used when running the server directly via `python run.py` or
    `python -m src.main`. It initializes everything and runs the full server.
    """
    try:
        # Setup Python logging first
        setup_python_logging()
        
        # Get and validate configuration
        config = get_config()
        
        # Log startup
        dual_logger.info("=" * 60)
        dual_logger.info("OAUTH HTTPS PROXY STARTING (CLI MODE)")
        dual_logger.info("=" * 60)
        dual_logger.info("Starting OAuth HTTPS Proxy via run.py...")
        dual_logger.info(f"Configuration loaded: HTTP={config.HTTP_PORT}, HTTPS={config.HTTPS_PORT}")
        
        # Run the server
        asyncio.run(run_server(config))
        
    except KeyboardInterrupt:
        dual_logger.info("Shutting down OAuth HTTPS Proxy (interrupted)")
        sys.exit(0)
    except Exception as e:
        # Log to both Python logger and stderr
        dual_logger.error(f"Failed to start OAuth HTTPS Proxy: {e}", error=e)
        print(f"ERROR: Failed to start OAuth HTTPS Proxy: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()