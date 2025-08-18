"""Main entry point for OAuth HTTPS Proxy."""

import asyncio
import logging
import sys
from typing import Optional

from .shared.config import Config, get_config
from .shared.utils import setup_logging
from .shared.logging import configure_logging, set_request_logger
from .shared.request_logger import RequestLogger
from .storage import RedisStorage
from .certmanager import CertificateManager, HTTPSServer, CertificateScheduler
from .proxy import ProxyHandler
from .dispatcher import UnifiedMultiInstanceServer
from .api.server import create_api_app
from .api.async_init import init_async_components, attach_to_app
from .orchestration.instance_workflow import InstanceWorkflowOrchestrator
from .docker.async_manager import AsyncDockerManager
from .certmanager.async_manager import AsyncCertificateManager

logger = logging.getLogger(__name__)

# Global instances
manager: Optional[CertificateManager] = None
https_server: Optional[HTTPSServer] = None
scheduler: Optional[CertificateScheduler] = None
proxy_handler: Optional[ProxyHandler] = None
logging_components: Optional[dict] = None
request_logger: Optional[RequestLogger] = None
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
    
    # Initialize request logger with async Redis first
    request_logger = RequestLogger(redis_url)
    
    # Configure structured logging with Redis and RequestLogger
    logging_components = configure_logging(storage.redis_client, request_logger)
    logger.info("Structured logging configured with Redis storage and IP capture")
    
    # Set the global request logger
    set_request_logger(request_logger)
    logger.info("Request logger initialized with Redis indexing")
    
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
    
    logger.info("All components initialized successfully")
    
    return storage, manager, scheduler, proxy_handler, workflow_orchestrator, async_components, https_server


async def run_server(config: Config) -> None:
    """Run the unified multi-instance server with async architecture."""
    # Initialize all components
    storage, manager, scheduler, proxy_handler, workflow_orchestrator, async_components, https_server = await initialize_components(config)
    
    # Create FastAPI app with async components attached
    app = create_api_app(storage, manager, scheduler)
    
    # Attach async components to app
    attach_to_app(app, async_components)
    
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
        
        await unified_server.run()
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
    """Main entry point."""
    try:
        # Get and validate configuration
        config = get_config()
        
        # Setup logging
        setup_logging(config.LOG_LEVEL)
        
        logger.info("Starting MCP HTTP Proxy...")
        logger.info(f"Configuration loaded: HTTP={config.HTTP_PORT}, HTTPS={config.HTTPS_PORT}")
        
        # Run the server
        asyncio.run(run_server(config))
        
    except KeyboardInterrupt:
        logger.info("Shutting down MCP HTTP Proxy (interrupted)")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to start MCP HTTP Proxy: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()