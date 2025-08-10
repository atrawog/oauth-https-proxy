"""Main entry point for MCP HTTP Proxy."""

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
from .orchestration.instance_workflow import InstanceWorkflowOrchestrator

logger = logging.getLogger(__name__)

# Global instances
manager: Optional[CertificateManager] = None
https_server: Optional[HTTPSServer] = None
scheduler: Optional[CertificateScheduler] = None
proxy_handler: Optional[ProxyHandler] = None
logging_components: Optional[dict] = None
request_logger: Optional[RequestLogger] = None
workflow_orchestrator: Optional[InstanceWorkflowOrchestrator] = None


def initialize_components(config: Config) -> None:
    """Initialize all system components."""
    global manager, https_server, scheduler, proxy_handler, logging_components, request_logger, workflow_orchestrator
    
    # Initialize storage with Redis URL
    redis_url = config.get_redis_url_with_password()
    storage = RedisStorage(redis_url)
    
    # Initialize request logger with async Redis first
    request_logger = RequestLogger(redis_url)
    
    # Configure structured logging with Redis and RequestLogger
    logging_components = configure_logging(storage.redis_client, request_logger)
    logger.info("Structured logging configured with Redis storage and IP capture")
    
    # Set the global request logger
    set_request_logger(request_logger)
    logger.info("Request logger initialized with Redis indexing")
    
    # Initialize certificate manager
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
        dispatcher=None  # Will be set later when dispatcher is created
    )
    logger.info(f"InstanceWorkflowOrchestrator created: {workflow_orchestrator}")
    
    # Initialize default routes
    storage.initialize_default_routes()
    
    # Initialize default proxies
    storage.initialize_default_proxies()
    
    logger.info("All components initialized successfully")


async def run_server(config: Config) -> None:
    """Run the unified multi-instance server."""
    # Initialize components
    initialize_components(config)
    
    # Start async Redis log handler if available
    if logging_components and logging_components.get("redis_handler"):
        await logging_components["redis_handler"].start()
        logger.info("Async Redis log handler started")
    
    # Create FastAPI app
    app = create_api_app(manager.storage, manager, scheduler)
    
    # Start scheduler
    scheduler.start()
    
    # Start workflow orchestrator
    logger.info("Starting workflow orchestrator...")
    await workflow_orchestrator.start()
    logger.info("Workflow orchestrator started successfully")
    
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
            redis_client=manager.storage.redis_client
        )
        proxy_task = asyncio.create_task(proxy_server.serve_forever())
        
        # Run unified multi-instance server for proxy domains
        unified_server = UnifiedMultiInstanceServer(
            https_server_instance=https_server,
            app=None,  # No app needed - just proxy instances
            host=config.SERVER_HOST
        )
        
        # Set server reference in workflow orchestrator (not just dispatcher)
        # The workflow needs access to the server's create_instance_for_proxy method
        workflow_orchestrator.dispatcher = unified_server
        logger.info("Workflow orchestrator linked to unified server")
        
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
        
        # Stop async Redis log handler
        if logging_components and logging_components.get("redis_handler"):
            await logging_components["redis_handler"].stop()
            logger.info("Async Redis log handler stopped")


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