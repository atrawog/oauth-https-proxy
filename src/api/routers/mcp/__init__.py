"""MCP (Model Context Protocol) router module.

This module provides an MCP server endpoint integrated with the OAuth HTTPS Proxy
system, offering tools for proxy management, certificate operations, and system
monitoring through the MCP protocol.
"""

from .mcp_router import create_mcp_router

__all__ = ["create_mcp_router"]
