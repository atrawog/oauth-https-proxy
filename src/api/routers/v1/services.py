"""Service management API endpoints (Docker and external services).

This module redirects to the modular service management structure.
"""

from .services import create_services_router


def create_router(storage):
    """Create the services API router (Docker and external).
    
    Uses ONLY async components from app.state - no sync fallbacks!
    
    Args:
        storage: Async Redis storage instance
    
    Returns:
        APIRouter with all service endpoints
    """
    # Everything is async - managers come from request.app.state
    return create_services_router(storage)
