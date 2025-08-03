"""ASGI app entry point that properly initializes all components."""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from .shared.config import get_config
from .shared.logging import configure_logging, set_request_logger
from .shared.request_logger import RequestLogger
from .storage import RedisStorage
from .certmanager import CertificateManager, HTTPSServer, CertificateScheduler
from .proxy import ProxyHandler
from .dispatcher import UnifiedMultiInstanceServer
from .api.server import create_api_app

logger = logging.getLogger(__name__)

# Global instances
manager = None
https_server = None
scheduler = None
proxy_handler = None
unified_server = None
request_logger = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    global manager, https_server, scheduler, proxy_handler, unified_server, request_logger
    
    logger.info("Starting MCP HTTP Proxy (ASGI mode)...")
    
    # Get configuration
    config = get_config()
    
    # Initialize storage with Redis URL
    redis_url = config.get_redis_url_with_password()
    storage = RedisStorage(redis_url)
    
    # Initialize request logger
    request_logger = RequestLogger(redis_url)
    
    # Configure structured logging
    logging_components = configure_logging(storage.redis_client, request_logger)
    set_request_logger(request_logger)
    
    # Start async Redis log handler
    if logging_components and logging_components.get("redis_handler"):
        await logging_components["redis_handler"].start()
    
    # Initialize certificate manager
    manager = CertificateManager(storage)
    
    # Initialize HTTPS server
    https_server = HTTPSServer(manager)
    https_server.load_certificates()
    
    # Initialize scheduler
    scheduler = CertificateScheduler(manager)
    scheduler.start()
    
    # Initialize proxy handler
    proxy_handler = ProxyHandler(storage)
    
    # Initialize default routes and proxies
    storage.initialize_default_routes()
    storage.initialize_default_proxies()
    
    # Create and start UnifiedMultiInstanceServer
    unified_server = UnifiedMultiInstanceServer(
        https_server_instance=https_server,
        app=None,  # Will create its own proxy apps
        host=config.SERVER_HOST
    )
    
    # Start the unified server in a background task
    unified_task = asyncio.create_task(unified_server.run())
    
    logger.info("All components initialized successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down MCP HTTP Proxy...")
    
    if scheduler:
        scheduler.stop()
    
    if proxy_handler:
        await proxy_handler.close()
    
    # Stop async Redis log handler
    if logging_components and logging_components.get("redis_handler"):
        await logging_components["redis_handler"].stop()


# Create the FastAPI app with proper initialization
config = get_config()

# Basic logging before structured logging is initialized
logging.basicConfig(level=getattr(logging, config.LOG_LEVEL.upper()))

# Initialize storage early to pass to create_api_app
redis_url = config.get_redis_url_with_password()
storage = RedisStorage(redis_url)

# Initialize components early for API creation
temp_manager = CertificateManager(storage)
temp_scheduler = CertificateScheduler(temp_manager)

# Create the app
app = create_api_app(storage, temp_manager, temp_scheduler)

# Override the lifespan to properly initialize everything
app.router.lifespan_context = lifespan

logger.info("ASGI app created and ready")