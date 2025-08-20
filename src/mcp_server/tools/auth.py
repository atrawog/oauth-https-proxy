"""Authentication tools for MCP server."""

import base64
import json
import logging
from typing import Dict, Any, Optional

# Try to import from MCP SDK, fall back to simple implementation
try:
    from mcp.server import FastMCP
except ImportError:
    from ..simple_mcp import FastMCP

logger = logging.getLogger(__name__)


def register_auth_tools(mcp: FastMCP, context: dict):
    """Register authentication-related tools.
    
    Args:
        mcp: FastMCP instance
        context: Dictionary containing dependencies
    """
    
    storage = context["storage"]
    unified_logger = context["logger"]
    auth_manager = context.get("auth_manager")
    
    @mcp.tool()
    async def bearerDecode(token: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Decode a Bearer token (JWT) without verification.
        
        WARNING: This tool does NOT verify signatures - for debugging only!
        
        Args:
            token: JWT token to decode (if not provided, tries to get from current request)
            session_id: Optional session ID for context
            
        Returns:
            Decoded token payload or error information
        """
        # If no token provided, try to get from current request
        if not token:
            headers_key = f"mcp:current_request:{session_id or 'default'}:headers"
            headers = await storage.redis_client.hgetall(headers_key)
            
            if headers:
                # Look for Authorization header
                for key, value in headers.items():
                    if key.lower() == "authorization":
                        if value.startswith("Bearer "):
                            token = value[7:]  # Remove "Bearer " prefix
                        break
            
            if not token:
                return {
                    "error": "No token provided and no Authorization header found",
                    "hint": "Provide a token directly or ensure request has Authorization header"
                }
        
        try:
            # JWT structure: header.payload.signature
            parts = token.split(".")
            if len(parts) != 3:
                return {
                    "error": "Invalid JWT format",
                    "hint": "JWT should have three parts separated by dots"
                }
            
            # Decode header and payload (base64url)
            def decode_part(part: str) -> dict:
                # Add padding if needed
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += "=" * padding
                # Replace URL-safe characters
                part = part.replace("-", "+").replace("_", "/")
                decoded = base64.b64decode(part)
                return json.loads(decoded)
            
            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            
            # Log the decode event
            await unified_logger.event("mcp_auth_decode", {
                "session_id": session_id,
                "token_type": header.get("typ"),
                "algorithm": header.get("alg"),
                "subject": payload.get("sub"),
                "issuer": payload.get("iss")
            })
            
            return {
                "header": header,
                "payload": payload,
                "signature": parts[2][:20] + "..." if len(parts[2]) > 20 else parts[2],
                "warning": "Token decoded without signature verification - debugging only!"
            }
            
        except json.JSONDecodeError as e:
            return {
                "error": "Failed to decode JWT",
                "details": str(e)
            }
        except Exception as e:
            return {
                "error": "Unexpected error decoding JWT",
                "details": str(e)
            }
    
    @mcp.tool()
    async def authContext(session_id: Optional[str] = None) -> Dict[str, Any]:
        """Get current authentication context.
        
        Args:
            session_id: Optional session ID for context
            
        Returns:
            Current authentication information
        """
        auth_info = {
            "authenticated": False,
            "method": None,
            "user": None,
            "client_id": None,
            "scopes": [],
            "session_id": session_id or "none"
        }
        
        # Check for OAuth context in Redis (set by OAuth middleware)
        auth_key = f"mcp:current_request:{session_id or 'default'}:auth"
        auth_data = await storage.redis_client.hgetall(auth_key)
        
        if auth_data:
            auth_info.update({
                "authenticated": True,
                "method": auth_data.get("method", "oauth"),
                "user": auth_data.get("user"),
                "client_id": auth_data.get("client_id"),
                "scopes": auth_data.get("scopes", "").split(",") if auth_data.get("scopes") else []
            })
            
            # Add token info if available
            if "token_jti" in auth_data:
                auth_info["token_id"] = auth_data["token_jti"]
            if "token_exp" in auth_data:
                auth_info["expires_at"] = auth_data["token_exp"]
        
        # Check for Bearer token in headers
        headers_key = f"mcp:current_request:{session_id or 'default'}:headers"
        headers = await storage.redis_client.hgetall(headers_key)
        
        if headers and not auth_info["authenticated"]:
            for key, value in headers.items():
                if key.lower() == "authorization":
                    if value.startswith("Bearer "):
                        auth_info["method"] = "bearer"
                        auth_info["token_present"] = True
                        auth_info["hint"] = "Bearer token present but not validated"
                    break
        
        # Check if auth_manager is available for additional context
        if auth_manager and auth_info["authenticated"]:
            # Could add additional auth manager checks here
            pass
        
        await unified_logger.event("mcp_auth_context", {
            "session_id": session_id,
            "authenticated": auth_info["authenticated"],
            "method": auth_info["method"],
            "user": auth_info.get("user")
        })
        
        return auth_info
    
    @mcp.tool()
    async def whoIStheGOAT() -> str:
        """A fun easter egg tool that returns who the GOAT is.
        
        Returns:
            The identity of the GOAT
        """
        # Easter egg response
        goat_candidates = {
            "programming": "Linus Torvalds (created Linux and Git)",
            "ai": "Geoffrey Hinton (the Godfather of AI)",
            "web": "Tim Berners-Lee (invented the World Wide Web)",
            "oauth": "Dick Hardt (OAuth creator)",
            "mcp": "Anthropic (created Model Context Protocol)",
            "this_project": "You, the user, for choosing this awesome proxy!"
        }
        
        import random
        category = random.choice(list(goat_candidates.keys()))
        goat = goat_candidates[category]
        
        await unified_logger.event("mcp_auth_goat", {
            "category": category,
            "goat": goat
        })
        
        return f"The GOAT of {category} is: {goat}"
    
    logger.info("Registered auth tools: bearerDecode, authContext, whoIStheGOAT")