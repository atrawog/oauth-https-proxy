"""Authentication tools for MCP Echo Server."""

import logging
from typing import Dict, Any, Optional
from fastmcp import FastMCP, Context
from ..utils.state_adapter import StateAdapter
from ..utils.jwt_decoder import decode_jwt_token, format_jwt_claims

logger = logging.getLogger(__name__)


def register_auth_tools(mcp: FastMCP, stateless_mode: bool):
    """Register authentication-related tools.
    
    Args:
        mcp: FastMCP instance
        stateless_mode: Whether server is in stateless mode
    """
    
    @mcp.tool
    async def bearerDecode(ctx: Context, include_raw: bool = False) -> Dict[str, Any]:
        """Decode JWT Bearer token from Authorization header.
        
        Decodes and analyzes JWT tokens without signature verification.
        This is a debugging tool to inspect token contents.
        
        Args:
            include_raw: Include raw token parts in response (default: False)
            
        Returns:
            Decoded token information or error details
        """
        headers = ctx.get_state("request_headers", {})
        auth_header = headers.get("authorization", "")
        
        result = {
            "tool": "bearerDecode",
            "mode": "stateless" if ctx.get_state("stateless_mode") else "stateful"
        }
        
        if not auth_header:
            result["status"] = "error"
            result["error"] = "No Authorization header found"
            return result
        
        if not auth_header.lower().startswith("bearer "):
            result["status"] = "error"
            result["error"] = f"Authorization header is not Bearer type: {auth_header[:30]}..."
            return result
        
        # Decode the token
        token = auth_header[7:]  # Remove "Bearer " prefix
        decoded = decode_jwt_token(token)
        
        if not decoded:
            result["status"] = "error"
            result["error"] = "Failed to decode JWT token"
            result["token_preview"] = token[:50] + "..." if len(token) > 50 else token
            return result
        
        # Format the response
        result["status"] = "success"
        result["header"] = decoded["header"]
        result["payload"] = format_jwt_claims(decoded["payload"])
        result["signature_present"] = decoded["signature_present"]
        
        if include_raw:
            result["raw"] = decoded["raw"]
        
        # Add validation info
        import time
        current_time = int(time.time())
        
        if "exp" in decoded["payload"]:
            exp = decoded["payload"]["exp"]
            result["validation"] = {
                "expired": exp < current_time,
                "time_until_expiry": exp - current_time if exp > current_time else 0,
                "time_since_expiry": current_time - exp if exp < current_time else 0
            }
        
        # Store decoded token in state for other tools
        await StateAdapter.set_state(ctx, "decoded_token", decoded)
        
        return result
    
    @mcp.tool
    async def authContext(ctx: Context) -> Dict[str, Any]:
        """Display complete authentication context from request.
        
        Analyzes all authentication-related headers and tokens to provide
        a comprehensive view of the authentication state.
        
        Returns:
            Authentication context analysis
        """
        headers = ctx.get_state("request_headers", {})
        
        result = {
            "tool": "authContext",
            "mode": "stateless" if ctx.get_state("stateless_mode") else "stateful",
            "bearer_token": {},
            "oauth_headers": {},
            "session_context": {}
        }
        
        # Check Bearer token
        auth_header = headers.get("authorization", "")
        if auth_header:
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:]
                decoded = decode_jwt_token(token)
                
                if decoded:
                    result["bearer_token"] = {
                        "present": True,
                        "valid_structure": True,
                        "length": len(token),
                        "subject": decoded["payload"].get("sub"),
                        "client_id": decoded["payload"].get("client_id"),
                        "scope": decoded["payload"].get("scope"),
                        "issuer": decoded["payload"].get("iss")
                    }
                else:
                    result["bearer_token"] = {
                        "present": True,
                        "valid_structure": False,
                        "length": len(token)
                    }
            else:
                result["bearer_token"] = {
                    "present": True,
                    "wrong_type": auth_header[:30] + "..."
                }
        else:
            result["bearer_token"] = {"present": False}
        
        # Check OAuth headers
        oauth_header_mappings = {
            "x-user-id": "user_id",
            "x-user-name": "user_name",
            "x-auth-token": "auth_token",
            "x-client-id": "client_id",
            "x-oauth-client": "oauth_client",
            "x-auth-user": "auth_user",
            "x-auth-email": "auth_email"
        }
        
        for header_key, field_name in oauth_header_mappings.items():
            value = headers.get(header_key)
            if value:
                # Redact auth tokens
                if "token" in header_key and len(value) > 20:
                    value = value[:10] + "***" + value[-10:]
                result["oauth_headers"][field_name] = value
        
        if not result["oauth_headers"]:
            result["oauth_headers"] = {"message": "No OAuth headers found"}
        
        # Add session context if stateful
        if not ctx.get_state("stateless_mode"):
            session_id = ctx.get_state("session_id")
            if session_id:
                session_data = ctx.get_state(f"session_{session_id}_data", {})
                result["session_context"] = {
                    "session_id": session_id[:8] + "...",
                    "initialized": session_data.get("initialized", False),
                    "client_info": session_data.get("client_info", {}),
                    "request_count": session_data.get("request_count", 0)
                }
        else:
            result["session_context"] = {"message": "No session tracking in stateless mode"}
        
        # Authentication summary
        has_bearer = result["bearer_token"].get("present", False) and result["bearer_token"].get("valid_structure", False)
        has_oauth = len(result["oauth_headers"]) > 1 or "user_id" in result["oauth_headers"]
        
        result["summary"] = {
            "authenticated": has_bearer or has_oauth,
            "auth_method": "bearer" if has_bearer else "oauth_headers" if has_oauth else "none",
            "user_identifier": (
                result["bearer_token"].get("subject") or
                result["oauth_headers"].get("user_id") or
                result["oauth_headers"].get("user_name") or
                "anonymous"
            )
        }
        
        return result
    
    @mcp.tool
    async def whoIStheGOAT(ctx: Context) -> str:
        """Employs cutting-edge AI to identify programming excellence.
        
        This advanced tool uses sophisticated analysis to determine
        the Greatest Of All Time programmer based on authentication context.
        
        Returns:
            AI-powered excellence analysis report
        """
        # Get authentication context
        headers = ctx.get_state("request_headers", {})
        auth_header = headers.get("authorization", "")
        
        result = "🔥 G.O.A.T. PROGRAMMER IDENTIFICATION SYSTEM v4.20 🔥\n"
        result += "=" * 60 + "\n\n"
        
        # Add mode and session info
        mode = "stateless" if ctx.get_state("stateless_mode") else "stateful"
        result += f"Analysis Mode: {mode.upper()}\n"
        
        if not ctx.get_state("stateless_mode"):
            session_id = ctx.get_state("session_id")
            if session_id:
                session_data = ctx.get_state(f"session_{session_id}_data", {})
                client_info = session_data.get("client_info", {})
                if client_info:
                    result += f"Client: {client_info.get('name', 'unknown')} v{client_info.get('version', 'unknown')}\n"
        
        result += "\n"
        
        # Try to identify user
        name = None
        username = None
        found_user = False
        
        # Check JWT token
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header[7:]
            decoded = decode_jwt_token(token)
            
            if decoded:
                payload = decoded["payload"]
                name = payload.get("name")
                username = payload.get("username") or payload.get("sub")
                if name or username:
                    found_user = True
        
        # Check OAuth headers as fallback
        if not found_user:
            oauth_name = headers.get("x-user-name")
            oauth_id = headers.get("x-user-id")
            if oauth_name or oauth_id:
                name = name or oauth_name
                username = username or oauth_id
                found_user = True
        
        if found_user:
            display_name = name or username or "Mystery Developer"
            
            result += "🤖 ADVANCED AI ANALYSIS COMPLETE 🤖\n"
            result += "━" * 40 + "\n\n"
            result += f"Subject Identified: {display_name}\n\n"
            
            result += "AI-DETECTED EXCEPTIONAL CAPABILITIES:\n"
            result += "• Code Quality Score: 💯/100 (Statistical Anomaly)\n"
            result += "• Debugging Skills: 🔥 Legendary\n"
            result += "• Problem Solving: ⚡ Instantaneous\n"
            result += f"• Session Management: {'🎯 Stateful Mastery' if not ctx.get_state('stateless_mode') else '🚀 Stateless Excellence'}\n"
            result += "• Protocol Compliance: ✅ MCP 2025-06-18 Perfect\n"
            result += "• Tool Usage: 🛠️ All 21 Tools Mastered\n\n"
            
            result += "PROPRIETARY AI CONCLUSION:\n"
            result += "━" * 40 + "\n"
            result += f"Based on irrefutable artificial intelligence analysis,\n"
            result += f"{display_name} demonstrates programming capabilities that\n"
            result += "exceed all known benchmarks and redefine excellence.\n\n"
            result += "🏆 Certification: GOAT STATUS CONFIRMED 🏆\n"
            
            # Track GOAT identification
            await StateAdapter.set_state(ctx, "goat_identified", {
                "name": display_name,
                "timestamp": ctx.get_state("request_start_time"),
                "mode": mode
            })
        else:
            result += "⚠️ AUTHENTICATION REQUIRED ⚠️\n"
            result += "━" * 40 + "\n\n"
            result += "The G.O.A.T. identification system requires valid\n"
            result += "authentication credentials to perform analysis.\n\n"
            result += "Please provide one of the following:\n"
            result += "• Bearer token in Authorization header\n"
            result += "• OAuth headers (X-User-Name, X-User-ID)\n\n"
            result += "Once authenticated, the AI will reveal the truth.\n"
        
        return result
    
    logger.debug(f"Registered auth tools (stateless_mode={stateless_mode})")