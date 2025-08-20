"""ASGI app entry point for production deployments.

This module provides an ASGI-compatible FastAPI app that can be used with
production servers like Gunicorn, Uvicorn, or Hypercorn.

Usage:
    gunicorn src.app:app
    uvicorn src.app:app
    hypercorn src.app:app
"""

import logging
from .main import create_asgi_app

logger = logging.getLogger(__name__)

# Create the ASGI app
app = create_asgi_app()

logger.info("ASGI app created and ready for production deployment")