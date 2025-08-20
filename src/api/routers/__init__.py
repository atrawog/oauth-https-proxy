"""API routers module.

Router registration is handled by the unified registry in registry.py
"""

# Import the registry for backward compatibility
from .registry import register_all_routers

__all__ = ['register_all_routers']