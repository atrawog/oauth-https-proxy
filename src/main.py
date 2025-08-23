"""Main entry point for OAuth HTTPS Proxy."""

import asyncio
import sys
from typing import Optional

from .shared.config import Config, get_config
from .shared.logger import log_debug, log_info, log_warning, log_error, log_trace
from .storage import RedisStorage
from .certmanager import CertificateManager, HTTPSServer, CertificateScheduler
from .proxy import ProxyHandler
from .dispatcher import UnifiedMultiInstanceServer
from .api.server import create_api_app
from .api.async_init import init_async_components
from .api.routers.registry import register_all_routers
from .docker.async_manager import AsyncDockerManager
from .certmanager.async_manager import AsyncCertificateManager

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
    
    # Initialize async components
    async_components = await init_async_components(redis_url)
    log_info("Async components initialized", component="main")
    
    # Logging is now handled by UnifiedAsyncLogger initialized in async_components
    log_info("Using UnifiedAsyncLogger for all logging", component="main")
    
    # Initialize certificate manager (sync for now, will be replaced by async)
    manager = CertificateManager(storage)
    
    # Initialize HTTPS server
    https_server = HTTPSServer(manager)
    https_server.load_certificates()
    
    # Initialize scheduler
    scheduler = CertificateScheduler(manager)
    
    # Initialize proxy handler
    proxy_handler = ProxyHandler(storage)
    
    # Initialize default routes
    storage.initialize_default_routes()
    
    # Initialize default proxies
    storage.initialize_default_proxies()
    
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
        
        # Initialize auth service
        from src.auth import FlexibleAuthService
        from src.auth.defaults import initialize_auth_system
        oauth_components = getattr(app.state, 'oauth_components', None)
        app.state.auth_service = FlexibleAuthService(
            storage=async_components.async_storage,
            oauth_components=oauth_components
        )
        
        # Initialize auth in background
        try:
            await app.state.auth_service.initialize()
            await initialize_auth_system(
                async_components.async_storage,
                load_defaults=True,
                migrate=True
            )
            log_info("✓ Flexible auth system initialized", component="main")
        except Exception as e:
            log_error(f"Failed to initialize auth: {e}", component="main")
        
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
    """Run the unified multi-instance server with async architecture."""
    # Initialize all components
    storage, manager, scheduler, proxy_handler, async_components, https_server = await initialize_components(config)
    
    # Create FastAPI app
    log_info("Creating FastAPI app...", component="main")
    app = create_api_app(storage, manager, scheduler)
    log_info("FastAPI app created successfully", component="main")
    
    # ========== ATTACH COMPONENTS DIRECTLY ==========
    log_info("Attaching async components to app state...", component="main")
    
    # Core components needed by routers
    app.state.async_components = async_components
    app.state.async_storage = async_components.async_storage
    app.state.unified_logger = async_components.unified_logger
    app.state.metrics_processor = async_components.metrics_processor
    app.state.alert_manager = async_components.alert_manager
    app.state.docker_manager = async_components.docker_manager
    app.state.cert_manager = async_components.cert_manager
    app.state.storage = storage  # Legacy storage still needed by some routers
    
    # Use AsyncLogStorage for request logging (already initialized in async_components)
    # The middleware will access it via app.state.async_storage
    log_info("Using AsyncLogStorage for request logging via Redis Streams", component="main")
    
    # Initialize auth service SYNCHRONOUSLY before router registration
    from src.auth import FlexibleAuthService
    from src.auth.defaults import initialize_auth_system
    oauth_components = getattr(app.state, 'oauth_components', None)
    app.state.auth_service = FlexibleAuthService(
        storage=async_components.async_storage,
        oauth_components=oauth_components
    )
    
    # Initialize auth SYNCHRONOUSLY - must complete before routers are registered
    try:
        await app.state.auth_service.initialize()
        await initialize_auth_system(
            async_components.async_storage,
            load_defaults=True,
            migrate=True
        )
        log_info("✓ Flexible auth system initialized BEFORE router registration", component="main")
    except Exception as e:
        log_error(f"Failed to initialize auth: {e}", component="main")
        # Don't continue if auth fails to initialize
        raise RuntimeError(f"Auth initialization failed: {e}")
    
    log_info("✓ All components attached to app state", component="main")
    
    # ========== REGISTER ALL ROUTERS USING UNIFIED REGISTRY ==========
    # Note: Auth service is now initialized and ready for AuthDep to use
    log_info("=" * 60, component="main")
    log_info("STARTING UNIFIED ROUTER REGISTRATION", component="main")
    log_info("=" * 60, component="main")
    log_info("Starting router registration with Unified Router Registry...", component="main")
    try:
        register_all_routers(app)
        log_info("✓ All routers registered successfully via Unified Router Registry", component="main")
    except Exception as e:
        log_error(f"✗ Router registration failed: {e}", component="main")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}", component="main")
        raise RuntimeError(f"Failed to register routers: {e}")
    
    # Start scheduler
    scheduler.start()
    
    try:
        # Start the FastAPI app on dual ports
        from hypercorn.asyncio import serve
        from hypercorn.config import Config as HypercornConfig
        from .middleware.proxy_protocol_handler import create_proxy_protocol_server
        
        # Port 9000 without PROXY protocol (for health checks and direct access)
        api_config = HypercornConfig()
        api_config.bind = ["0.0.0.0:9000"]
        api_config.loglevel = config.LOG_LEVEL.upper()
        
        log_info("Starting FastAPI app on port 9000 (no PROXY protocol)", component="main")
        api_task = asyncio.create_task(serve(app, api_config))
        
        # Port 9001 - internal Hypercorn without PROXY protocol
        internal_config = HypercornConfig()
        internal_config.bind = ["127.0.0.1:9001"]
        internal_config.loglevel = config.LOG_LEVEL.upper()
        
        log_info("Starting internal FastAPI app on port 9001", component="main")
        internal_task = asyncio.create_task(serve(app, internal_config))
        
        # Port 10001 - PROXY protocol handler forwarding to 9001
        log_info("Starting PROXY protocol handler on port 10001 -> 9001", component="main")
        proxy_server = await create_proxy_protocol_server(
            backend_host="127.0.0.1",
            backend_port=9001,
            listen_host="127.0.0.1", 
            listen_port=10001,
            redis_client=async_components.redis_clients.async_redis
        )
        proxy_task = asyncio.create_task(proxy_server.serve_forever())
        
        # Run unified multi-instance server for proxy domains
        log_info(f"Creating UnifiedMultiInstanceServer with https_server={https_server is not None}", component="main")
        try:
            unified_server = UnifiedMultiInstanceServer(
                https_server_instance=https_server,
                app=None,  # No app needed - just proxy instances
                host=config.SERVER_HOST,
                async_components=async_components,
                storage=storage  # Pass the sync storage for compatibility
            )
            log_info("UnifiedMultiInstanceServer created successfully", component="main")
        except Exception as e:
            log_error(f"Failed to create UnifiedMultiInstanceServer: {e}", component="main")
            import traceback
            traceback.print_exc()
            raise
        
        log_info(f"Starting MCP HTTP Proxy on ports {config.HTTP_PORT} (HTTP) and {config.HTTPS_PORT} (HTTPS)", component="main")
        log_info("Each domain will have its own dedicated Hypercorn instance", component="main")
        
        # Start the unified dispatcher
        log_info("Starting unified dispatcher (HTTP/HTTPS servers)...", component="main")
        try:
            # Start unified_server.run() as a task
            unified_task = asyncio.create_task(unified_server.run())
            log_info("Unified dispatcher started", component="main")
        except Exception as e:
            log_error(f"Failed to start unified dispatcher: {e}", component="main")
            import traceback
            traceback.print_exc()
            raise
        
        # Wait for all tasks
        await asyncio.gather(
            api_task,
            internal_task,
            proxy_task,
            unified_task,
            return_exceptions=True
        )
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
    try:
        # Get and validate configuration
        config = get_config()
        
        # Setup logging
        log_info("=" * 60, component="main")
        log_info("OAUTH HTTPS PROXY STARTING (CLI MODE)", component="main")
        log_info("=" * 60, component="main")
        log_info("Starting OAuth HTTPS Proxy via run.py...", component="main")
        log_info(f"Configuration loaded: HTTP={config.HTTP_PORT}, HTTPS={config.HTTPS_PORT}", component="main")
        
        # Run the server
        asyncio.run(run_server(config))
        
    except KeyboardInterrupt:
        log_info("Shutting down OAuth HTTPS Proxy (interrupted)", component="main")
        sys.exit(0)
    except Exception as e:
        log_error(f"Failed to start OAuth HTTPS Proxy: {e}", component="main")
        sys.exit(1)


if __name__ == "__main__":
    main()