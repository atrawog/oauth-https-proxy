"""Tests for MCP server functionality."""

import json
import pytest
import httpx
from typing import Dict, Any


# Base URL for tests (adjust as needed)
BASE_URL = "http://localhost:9000/api/v1"
MCP_URL = f"{BASE_URL}/mcp"


class TestMCPEndpoint:
    """Test MCP endpoint functionality."""
    
    @pytest.mark.asyncio
    async def test_mcp_health(self):
        """Test MCP health endpoint."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{MCP_URL}/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert "server" in data
            assert data["tools"] == 21  # We have 21 tools
    
    @pytest.mark.asyncio
    async def test_mcp_info(self):
        """Test MCP info endpoint."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{MCP_URL}/info")
            assert response.status_code == 200
            data = response.json()
            assert "name" in data
            assert "version" in data
            assert "protocolVersion" in data
            assert data["protocolVersion"] == "2025-06-18"
    
    @pytest.mark.asyncio
    async def test_mcp_initialize(self):
        """Test MCP initialize method."""
        async with httpx.AsyncClient() as client:
            request_data = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "clientInfo": {
                        "name": "test-client",
                        "version": "1.0.0"
                    }
                },
                "id": 1
            }
            
            response = await client.post(
                f"{MCP_URL}/",
                json=request_data,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 200
            assert "Mcp-Session-Id" in response.headers
            
            data = response.json()
            assert data["jsonrpc"] == "2.0"
            assert "result" in data
            assert data["result"]["protocolVersion"] == "2025-06-18"
            assert "capabilities" in data["result"]
    
    @pytest.mark.asyncio
    async def test_mcp_tools_list(self):
        """Test listing available tools."""
        async with httpx.AsyncClient() as client:
            request_data = {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": 2
            }
            
            response = await client.post(
                f"{MCP_URL}/",
                json=request_data,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert "result" in data
            assert "tools" in data["result"]
            
            tools = data["result"]["tools"]
            assert len(tools) == 21  # We have 21 tools
            
            # Check for specific tools
            tool_names = [tool["name"] for tool in tools]
            assert "echo" in tool_names
            assert "healthProbe" in tool_names
            assert "stateInspector" in tool_names
    
    @pytest.mark.asyncio
    async def test_mcp_tool_call(self):
        """Test calling a tool."""
        async with httpx.AsyncClient() as client:
            # First initialize to get session
            init_request = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
                "id": 1
            }
            
            init_response = await client.post(
                f"{MCP_URL}/",
                json=init_request
            )
            session_id = init_response.headers.get("Mcp-Session-Id")
            
            # Now call echo tool
            tool_request = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {
                        "message": "Hello MCP!"
                    }
                },
                "id": 3
            }
            
            response = await client.post(
                f"{MCP_URL}/",
                json=tool_request,
                headers={
                    "Content-Type": "application/json",
                    "Mcp-Session-Id": session_id
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            assert "result" in data
            assert "content" in data["result"]
    
    @pytest.mark.asyncio
    async def test_mcp_error_handling(self):
        """Test error handling for invalid requests."""
        async with httpx.AsyncClient() as client:
            # Test invalid JSON
            response = await client.post(
                f"{MCP_URL}/",
                content="invalid json",
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == 200  # JSON-RPC errors return 200
            data = response.json()
            assert "error" in data
            assert data["error"]["code"] == -32700  # Parse error
            
            # Test unknown method
            unknown_method = {
                "jsonrpc": "2.0",
                "method": "unknown/method",
                "params": {},
                "id": 4
            }
            
            response = await client.post(
                f"{MCP_URL}/",
                json=unknown_method
            )
            
            assert response.status_code == 200
            data = response.json()
            assert "error" in data
            assert data["error"]["code"] == -32601  # Method not found
    
    @pytest.mark.asyncio
    async def test_mcp_session_persistence(self):
        """Test session persistence in stateful mode."""
        async with httpx.AsyncClient() as client:
            # Initialize and get session
            init_request = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
                "id": 1
            }
            
            response = await client.post(f"{MCP_URL}/", json=init_request)
            session_id = response.headers.get("Mcp-Session-Id")
            assert session_id
            
            # Call echo tool with session
            echo_request = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {"message": "Test message"}
                },
                "id": 2
            }
            
            response1 = await client.post(
                f"{MCP_URL}/",
                json=echo_request,
                headers={"Mcp-Session-Id": session_id}
            )
            assert response1.status_code == 200
            
            # Call with same session again
            response2 = await client.post(
                f"{MCP_URL}/",
                json=echo_request,
                headers={"Mcp-Session-Id": session_id}
            )
            assert response2.status_code == 200
            
            # Both should have same session ID
            assert response1.headers.get("Mcp-Session-Id") == session_id
            assert response2.headers.get("Mcp-Session-Id") == session_id


class TestMCPTools:
    """Test individual MCP tools."""
    
    @pytest.mark.asyncio
    async def test_echo_tool(self):
        """Test the echo tool functionality."""
        # This would test the actual tool execution
        # For now, it's a placeholder
        pass
    
    @pytest.mark.asyncio
    async def test_health_probe_tool(self):
        """Test the healthProbe tool."""
        # This would test the actual tool execution
        pass
    
    @pytest.mark.asyncio
    async def test_state_inspector_tool(self):
        """Test the stateInspector tool."""
        # This would test the actual tool execution
        pass


# Helper functions for testing

async def call_mcp_method(
    method: str,
    params: Dict[str, Any] = None,
    session_id: str = None
) -> Dict[str, Any]:
    """Helper to call MCP methods."""
    request_data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": 1
    }
    
    headers = {"Content-Type": "application/json"}
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{MCP_URL}/",
            json=request_data,
            headers=headers
        )
        return response.json(), response.headers


async def initialize_mcp_session() -> str:
    """Initialize MCP session and return session ID."""
    result, headers = await call_mcp_method(
        "initialize",
        {"protocolVersion": "2025-06-18"}
    )
    return headers.get("Mcp-Session-Id")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])