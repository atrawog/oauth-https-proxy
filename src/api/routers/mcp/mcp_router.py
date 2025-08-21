"""MCP Router that handles both /mcp and /mcp/ without redirects.

This module creates a FastAPI router that properly integrates the SDK's
Starlette app while avoiding the /mcp to /mcp/ redirect issue.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Request, Response
from starlette.applications import Starlette

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_starlette import create_mcp_starlette_app

logger = logging.getLogger(__name__)


def create_mcp_router(
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> APIRouter:
    """Create MCP router that handles requests without trailing slash redirects."""
    
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("[MCP ROUTER] Creating MCP router")
    
    # Create the MCP Starlette app
    mcp_app = create_mcp_starlette_app(async_storage, cert_manager, docker_manager, unified_logger)
    
    # Create router
    router = APIRouter(tags=["mcp"])
    
    # Handler for all MCP requests at both /mcp and /mcp/
    @router.api_route("", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
    @router.api_route("/", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
    async def handle_mcp(request: Request) -> Response:
        """Handle MCP requests through the SDK's Starlette app."""
        logger.info(f"[MCP HANDLER] {request.method} {request.url.path}")
        
        # Build ASGI scope for the MCP app
        # The SDK expects the path to be "/" since we configured streamable_http_path="/"
        scope = {
            'type': 'http',
            'asgi': {'version': '3.0'},
            'http_version': '1.1',
            'method': request.method,
            'path': '/',  # SDK expects "/" since we set streamable_http_path="/"
            'root_path': '',
            'scheme': request.url.scheme,
            'query_string': request.url.query.encode() if request.url.query else b'',
            'headers': [(k.encode(), v.encode()) for k, v in request.headers.items()],
            'server': (request.client.host if request.client else '127.0.0.1',
                      request.client.port if request.client else 80),
            'client': (request.client.host if request.client else '127.0.0.1',
                      request.client.port if request.client else 0),
            'state': {}
        }
        
        # Get request body
        body = await request.body()
        
        # Create receive callable
        async def receive():
            return {
                'type': 'http.request',
                'body': body,
                'more_body': False
            }
        
        # Collect response
        response_started = False
        response_status = 200
        response_headers = []
        response_body = []
        
        async def send(message):
            nonlocal response_started, response_status, response_headers, response_body
            if message['type'] == 'http.response.start':
                response_started = True
                response_status = message.get('status', 200)
                response_headers = message.get('headers', [])
                logger.debug(f"[MCP RESPONSE START] Status: {response_status}")
            elif message['type'] == 'http.response.body':
                body_chunk = message.get('body', b'')
                if body_chunk:
                    response_body.append(body_chunk)
                    logger.debug(f"[MCP RESPONSE BODY] {len(body_chunk)} bytes")
        
        # Call the MCP app
        await mcp_app(scope, receive, send)
        
        # Build response
        headers_dict = {}
        for name, value in response_headers:
            name_str = name.decode('utf-8') if isinstance(name, bytes) else name
            value_str = value.decode('utf-8') if isinstance(value, bytes) else value  
            headers_dict[name_str] = value_str
        
        final_body = b''.join(response_body)
        logger.info(f"[MCP RESPONSE] Status: {response_status}, Size: {len(final_body)}")
        
        return Response(
            content=final_body,
            status_code=response_status,
            headers=headers_dict
        )
    
    logger.info("[MCP ROUTER] MCP router created successfully")
    return router