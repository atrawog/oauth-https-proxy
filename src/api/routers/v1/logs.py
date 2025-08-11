"""Log query API endpoints.

This module redirects to the modular log management structure.
"""

from .logs import create_logs_router


def create_router(storage):
    """Create the logs API router.
    
    This function maintains backward compatibility while using 
    the new modular structure.
    
    Args:
        async_storage: Redis async_storage instance
    
    Returns:
        APIRouter with all log endpoints
    """
    return create_logs_router(async_storage)
