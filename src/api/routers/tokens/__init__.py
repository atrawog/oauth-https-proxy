"""Token management router aggregation.

This module combines all token-related sub-routers into a single router.
"""

from fastapi import APIRouter

from .core import create_core_router
from .management import create_management_router
from .ownership import create_ownership_router
from .admin import create_admin_router


def create_tokens_router(async_storage):
    """Create the main tokens router combining all sub-routers.
    
    Args:
        async_storage: Redis async_storage instance
    
    Returns:
        APIRouter with all token endpoints
    """
    router = APIRouter()
    
    # Include sub-routers
    core_router = create_core_router(async_storage)
    router.include_router(core_router, tags=["token-core"])
    
    management_router = create_management_router(async_storage)
    router.include_router(management_router, tags=["token-management"])
    
    ownership_router = create_ownership_router(async_storage)
    router.include_router(ownership_router, tags=["token-ownership"])
    
    admin_router = create_admin_router(async_storage)
    router.include_router(admin_router, tags=["token-admin"])
    
    return router