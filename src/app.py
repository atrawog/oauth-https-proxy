"""ASGI app entry point for production deployments.

This module provides an ASGI-compatible FastAPI app that can be used with
production servers like Gunicorn, Uvicorn, or Hypercorn.

Usage:
    gunicorn src.app:create_app()
    uvicorn src.app:create_app --factory
    hypercorn src.app:create_app()
    
Or for backward compatibility:
    gunicorn src.app:app  (will create app on first access)
"""

import logging
import os

logger = logging.getLogger(__name__)

# Check if we're in ASGI mode (being imported by an ASGI server)
# ASGI servers typically set certain environment variables or import patterns
_app = None

def create_app():
    """Factory function to create the ASGI app."""
    from .main import create_asgi_app
    logger.info("Creating ASGI app via factory function")
    return create_asgi_app()

# Only create app if this module is being directly executed or imported by ASGI server
# Don't create if just being imported by other modules
if __name__ == "__main__" or "gunicorn" in os.environ.get("SERVER_SOFTWARE", "") or os.environ.get("ASGI_SERVER"):
    app = create_app()
else:
    # Defer app creation until actually accessed
    class AppProxy:
        def __getattr__(self, name):
            global _app
            if _app is None:
                _app = create_app()
            return getattr(_app, name)
    
    app = AppProxy()