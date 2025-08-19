"""MCP tools for oauth-https-proxy."""

from .echo import register_echo_tools
from .debug import register_debug_tools
from .auth import register_auth_tools
from .system import register_system_tools
from .state import register_state_tools

__all__ = [
    "register_echo_tools",
    "register_debug_tools",
    "register_auth_tools",
    "register_system_tools",
    "register_state_tools",
]