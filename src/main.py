"""Main entry point for OAuth HTTPS Proxy."""

import asyncio
import logging
import sys
from typing import Optional

from .shared.config import Config, get_config
from .shared.utils import setup_logging
# Legacy logging imports removed - using UnifiedAsyncLogger now
from .storage import RedisStorage
from .certmanager import CertificateManager, HTTPSServer, CertificateScheduler
from .proxy import ProxyHandler
from .dispatcher import UnifiedMultiInstanceServer
from .api.server import create_api_app
from .api.async_init import init_async_components
from .api.routers.registry import register_all_routers
from .orchestration.instance_workflow import InstanceWorkflowOrchestrator
from .docker.async_manager import AsyncDockerManager
from .certmanager.async_manager import AsyncCertificateManager

logger = logging.getLogger(__name__)

# Global instances
manager: Optional[CertificateManager] = None
https_server: Optional[HTTPSServer] = None
scheduler: Optional[CertificateScheduler] = None
proxy_handler: Optional[ProxyHandler] = None
workflow_orchestrator: Optional[InstanceWorkflowOrchestrator] = None


async def initialize_components(config: Config) -> tuple:
    """Initialize all system components with async architecture.
    
    Returns:
        Tuple of (storage, manager, scheduler, proxy_handler, workflow_orchestrator, async_components)
    """
    # Initialize storage with Redis URL
    redis_url = config.get_redis_url_with_password()
    storage = RedisStorage(redis_url)
    
    # Initialize async components
    async_components = await init_async_components(redis_url)
    logger.info("Async components initialized")
    
    # Logging is now handled by UnifiedAsyncLogger initialized in async_components
    logger.info("Using UnifiedAsyncLogger for all logging")
    
    # Initialize certificate manager (sync for now, will be replaced by async)
    manager = CertificateManager(storage)
    
    # Initialize HTTPS server
    https_server = HTTPSServer(manager)
    https_server.load_certificates()
    
    # Initialize scheduler
    scheduler = CertificateScheduler(manager)
    
    # Initialize proxy handler
    proxy_handler = ProxyHandler(storage)
    
    # Initialize workflow orchestrator
    logger.info("Creating InstanceWorkflowOrchestrator...")
    workflow_orchestrator = InstanceWorkflowOrchestrator(
        redis_url=redis_url,
        storage=storage,
        cert_manager=manager,
        dispatcher=None,  # Will be set later when dispatcher is created
        async_components=async_components
    )
    logger.info(f"InstanceWorkflowOrchestrator created: {workflow_orchestrator}")
    
    # Initialize default routes
    storage.initialize_default_routes()
    
    # Initialize default proxies
    storage.initialize_default_proxies()
    
    # Note: Flexible auth system is initialized directly in run_server()
    
    logger.info("All components initialized successfully")
    
    return storage, manager, scheduler, proxy_handler, workflow_orchestrator, async_components, https_server


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
        setup_logging(config.LOG_LEVEL)
        
        logger.info("Starting OAuth HTTPS Proxy (ASGI mode)...")
        
        # Initialize all components
        storage, manager, scheduler, proxy_handler, workflow_orchestrator, async_components, https_server = await initialize_components(config)
        
        # Create base API app
        # Note: We don't use create_api_app here to avoid circular dependencies
        # Instead we'll attach everything directly
        
        # Store core components in app state
        app.state.storage = storage
        app.state.cert_manager = manager
        app.state.scheduler = scheduler
        app.state.https_server = https_server
        app.state.proxy_handler = proxy_handler
        app.state.workflow_orchestrator = workflow_orchestrator
        
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
        logger.info("Using AsyncLogStorage for request logging via Redis Streams")
        
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
            logger.info("✓ Flexible auth system initialized")
        except Exception as e:
            logger.error(f"Failed to initialize auth: {e}")
        
        # Register all routers using unified registry
        logger.info("Registering all routers with Unified Router Registry...")
        try:
            from .api.routers.registry import register_all_routers
            register_all_routers(app)
            logger.info("✓ All routers registered successfully")
        except Exception as e:
            logger.error(f"✗ Router registration failed: {e}")
            raise
        
        # Start scheduler
        scheduler.start()
        
        # For ASGI mode, we don't start the full server here
        logger.info("ASGI app initialized and ready")
        
        yield
        
        # Shutdown
        logger.info("Shutting down OAuth HTTPS Proxy...")
        scheduler.stop()
        if proxy_handler:
            await proxy_handler.close()
        if workflow_orchestrator:
            await workflow_orchestrator.close()
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
    storage, manager, scheduler, proxy_handler, workflow_orchestrator, async_components, https_server = await initialize_components(config)
    
    # Create FastAPI app
    logger.info("Creating FastAPI app...")
    app = create_api_app(storage, manager, scheduler)
    logger.info("FastAPI app created successfully")
    
    # ========== ATTACH COMPONENTS DIRECTLY ==========
    logger.info("Attaching async components to app state...")
    
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
    logger.info("Using AsyncLogStorage for request logging via Redis Streams")
    
    # Initialize auth service
    from src.auth import FlexibleAuthService
    from src.auth.defaults import initialize_auth_system
    oauth_components = getattr(app.state, 'oauth_components', None)
    app.state.auth_service = FlexibleAuthService(
        storage=async_components.async_storage,
        oauth_components=oauth_components
    )
    
    # Initialize auth in background
    async def init_auth():
        try:
            await app.state.auth_service.initialize()
            await initialize_auth_system(
                async_components.async_storage,
                load_defaults=True,
                migrate=True
            )
            logger.info("✓ Flexible auth system initialized")
        except Exception as e:
            logger.error(f"Failed to initialize auth: {e}")
    
    asyncio.create_task(init_auth())
    
    logger.info("✓ All components attached to app state")
    
    # ========== REGISTER ALL ROUTERS USING UNIFIED REGISTRY ==========
    logger.info("=" * 60)
    logger.info("STARTING UNIFIED ROUTER REGISTRATION")
    logger.info("=" * 60)
    logger.info("Starting router registration with Unified Router Registry...")
    try:
        register_all_routers(app)
        logger.info("✓ All routers registered successfully via Unified Router Registry")
    except Exception as e:
        logger.error(f"✗ Router registration failed: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
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
        
        logger.info("Starting FastAPI app on port 9000 (no PROXY protocol)")
        api_task = asyncio.create_task(serve(app, api_config))
        
        # Port 9001 - internal Hypercorn without PROXY protocol
        internal_config = HypercornConfig()
        internal_config.bind = ["127.0.0.1:9001"]
        internal_config.loglevel = config.LOG_LEVEL.upper()
        
        logger.info("Starting internal FastAPI app on port 9001")
        internal_task = asyncio.create_task(serve(app, internal_config))
        
        # Port 10001 - PROXY protocol handler forwarding to 9001
        logger.info("Starting PROXY protocol handler on port 10001 -> 9001")
        proxy_server = await create_proxy_protocol_server(
            backend_host="127.0.0.1",
            backend_port=9001,
            listen_host="127.0.0.1", 
            listen_port=10001,
            redis_client=async_components.redis_clients.async_redis
        )
        proxy_task = asyncio.create_task(proxy_server.serve_forever())
        
        # Run unified multi-instance server for proxy domains
        unified_server = UnifiedMultiInstanceServer(
            https_server_instance=https_server,
            app=None,  # No app needed - just proxy instances
            host=config.SERVER_HOST,
            async_components=async_components
        )
        
        # Set server reference in workflow orchestrator
        workflow_orchestrator.dispatcher = unified_server
        logger.info("Workflow orchestrator linked to unified server")
        
        # Start workflow orchestrator AFTER dispatcher is set
        logger.info("Starting workflow orchestrator...")
        await workflow_orchestrator.start()
        logger.info("Workflow orchestrator started successfully")
        
        logger.info(f"Starting MCP HTTP Proxy on ports {config.HTTP_PORT} (HTTP) and {config.HTTPS_PORT} (HTTPS)")
        logger.info("Each domain will have its own dedicated Hypercorn instance")
        
        # Create unified server task
        unified_task = asyncio.create_task(unified_server.run())
        
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
        
        # Stop workflow orchestrator
        await workflow_orchestrator.close()
        logger.info("Workflow orchestrator stopped")
        
        # Shutdown async components
        await async_components.shutdown()
        logger.info("Async components shut down")


def main() -> None:
    """Main entry point for CLI execution.
    
    This is used when running the server directly via `python run.py` or
    `python -m src.main`. It initializes everything and runs the full server.
    """
    try:
        # Get and validate configuration
        config = get_config()
        
        # Setup logging
        setup_logging(config.LOG_LEVEL)
        
        logger.info("=" * 60)
        logger.info("OAUTH HTTPS PROXY STARTING (CLI MODE)")
        logger.info("=" * 60)
        logger.info("Starting OAuth HTTPS Proxy via run.py...")
        logger.info(f"Configuration loaded: HTTP={config.HTTP_PORT}, HTTPS={config.HTTPS_PORT}")
        
        # Run the server
        asyncio.run(run_server(config))
        
    except KeyboardInterrupt:
        logger.info("Shutting down OAuth HTTPS Proxy (interrupted)")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to start OAuth HTTPS Proxy: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()