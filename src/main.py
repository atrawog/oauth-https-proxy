"""Main entry point for MCP HTTP Proxy."""

import asyncio
import logging
import sys
from typing import Optional

from .shared.config import Config, get_config
from .shared.utils import setup_logging
from .storage import RedisStorage
from .certmanager import CertificateManager, HTTPSServer, CertificateScheduler
from .proxy import ProxyHandler
from .dispatcher import UnifiedMultiInstanceServer
from .api.server import create_api_app

logger = logging.getLogger(__name__)

# Global instances
manager: Optional[CertificateManager] = None
https_server: Optional[HTTPSServer] = None
scheduler: Optional[CertificateScheduler] = None
proxy_handler: Optional[ProxyHandler] = None


def initialize_components(config: Config) -> None:
    """Initialize all system components."""
    global manager, https_server, scheduler, proxy_handler
    
    # Initialize storage with Redis URL
    redis_url = config.get_redis_url_with_password()
    storage = RedisStorage(redis_url)
    
    # Initialize certificate manager
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
    
    logger.info("All components initialized successfully")


async def run_server(config: Config) -> None:
    """Run the unified multi-instance server."""
    # Initialize components
    initialize_components(config)
    
    # Create FastAPI app
    app = create_api_app(manager.storage, manager, scheduler)
    
    # Start scheduler
    scheduler.start()
    
    try:
        # Start the FastAPI app on port 9000
        from hypercorn.asyncio import serve
        from hypercorn.config import Config as HypercornConfig
        
        api_config = HypercornConfig()
        api_config.bind = ["127.0.0.1:9000"]
        api_config.loglevel = config.LOG_LEVEL.upper()
        
        logger.info("Starting FastAPI app on port 9000")
        api_task = asyncio.create_task(serve(app, api_config))
        
        # Run unified multi-instance server for proxy domains
        unified_server = UnifiedMultiInstanceServer(
            https_server_instance=https_server,
            app=None,  # No app needed - just proxy instances
            host=config.SERVER_HOST
        )
        
        logger.info(f"Starting MCP HTTP Proxy on ports {config.HTTP_PORT} (HTTP) and {config.HTTPS_PORT} (HTTPS)")
        logger.info("Each domain will have its own dedicated Hypercorn instance")
        
        await unified_server.run()
    finally:
        scheduler.stop()
        if proxy_handler:
            await proxy_handler.close()


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