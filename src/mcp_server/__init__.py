"""MCP (Model Context Protocol) server implementation for oauth-https-proxy.

Note: This module is named 'mcp_server' instead of 'mcp' to avoid
conflicts with the installed 'mcp' package from modelcontextprotocol/python-sdk.
"""

from .fastmcp_server import create_mcp_router, OAuthProxyMCPServer

__all__ = ["create_mcp_router", "OAuthProxyMCPServer"]