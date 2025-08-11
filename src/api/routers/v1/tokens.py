"""Token management API endpoints.

This module redirects to the modular token management structure.
"""

from .tokens import create_tokens_router


def create_router(async_storage):
    """Create the tokens API router.
    
    This function maintains backward compatibility while using 
    the new modular structure.
    
    Args:
        async_storage: Async Redis storage instance
    
    Returns:
        APIRouter with all token endpoints
    """
    return create_tokens_router(async_storage)
