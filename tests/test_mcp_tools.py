"""Comprehensive test suite for all MCP tools using MCP client pattern."""

import asyncio
import json
import time
import uuid
from typing import Any, Dict, List, Optional
import pytest
import httpx
import logging

logger = logging.getLogger(__name__)

# MCP endpoint configuration
MCP_BASE_URL = "http://localhost:9000/api/v1/mcp"


class MCPClient:
    """MCP Client for testing the MCP server."""
    
    def __init__(self, base_url: str = MCP_BASE_URL):
        """Initialize MCP client.
        
        Args:
            base_url: Base URL for MCP endpoint
        """
        self.base_url = base_url
        self.session_id: Optional[str] = None
        self.client = httpx.AsyncClient(timeout=30.0)
        self.request_id = 0
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def close(self):
        """Close the client."""
        await self.client.aclose()
    
    def _next_id(self) -> int:
        """Get next request ID."""
        self.request_id += 1
        return self.request_id
    
    async def request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Send JSON-RPC request to MCP server.
        
        Args:
            method: JSON-RPC method name
            params: Method parameters
            
        Returns:
            Response result
            
        Raises:
            Exception: If request fails or returns error
        """
        request_data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._next_id()
        }
        
        headers = {"Content-Type": "application/json"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        
        response = await self.client.post(
            f"{self.base_url}/",
            json=request_data,
            headers=headers
        )
        
        # Update session ID from response
        if "Mcp-Session-Id" in response.headers:
            self.session_id = response.headers["Mcp-Session-Id"]
        
        response_data = response.json()
        
        # Check for errors
        if "error" in response_data:
            error = response_data["error"]
            raise Exception(f"MCP Error {error['code']}: {error['message']}")
        
        return response_data.get("result", {})
    
    async def initialize(
        self,
        protocol_version: str = "2025-06-18",
        client_info: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Initialize MCP session.
        
        Args:
            protocol_version: MCP protocol version
            client_info: Client information
            
        Returns:
            Initialization result
        """
        if not client_info:
            client_info = {
                "name": "mcp-test-client",
                "version": "1.0.0"
            }
        
        result = await self.request("initialize", {
            "protocolVersion": protocol_version,
            "clientInfo": client_info
        })
        
        # Send initialized confirmation
        await self.request("initialized", {})
        
        return result
    
    async def list_tools(self) -> List[Dict[str, str]]:
        """List available tools.
        
        Returns:
            List of tool definitions
        """
        result = await self.request("tools/list")
        return result.get("tools", [])
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Call an MCP tool.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            
        Returns:
            Tool result
        """
        result = await self.request("tools/call", {
            "name": tool_name,
            "arguments": arguments or {}
        })
        
        # Extract content from response
        content = result.get("content", [])
        if content and isinstance(content, list):
            # Return text content if available
            for item in content:
                if item.get("type") == "text":
                    return item.get("text")
        
        return result


class TestMCPTools:
    """Test all 21 MCP tools."""
    
    @pytest.mark.asyncio
    async def test_mcp_server_health(self):
        """Test MCP server health endpoint."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{MCP_BASE_URL}/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["tools"] == 21
    
    @pytest.mark.asyncio
    async def test_mcp_initialization(self):
        """Test MCP client initialization."""
        async with MCPClient() as client:
            assert client.session_id is not None
            logger.info(f"Initialized with session: {client.session_id}")
    
    @pytest.mark.asyncio
    async def test_list_all_tools(self):
        """Test listing all available tools."""
        async with MCPClient() as client:
            tools = await client.list_tools()
            
            # Verify we have all 21 tools
            assert len(tools) == 21
            
            # Verify all expected tools are present
            expected_tools = [
                # Echo tools
                "echo", "replayLastEcho",
                # Debug tools
                "printHeader", "requestTiming", "corsAnalysis", "environmentDump",
                # Auth tools
                "bearerDecode", "authContext", "whoIStheGOAT",
                # System tools
                "healthProbe", "sessionInfo",
                # State tools
                "stateInspector", "sessionHistory", "stateManipulator",
                "sessionCompare", "sessionTransfer", "stateBenchmark",
                "sessionLifecycle", "stateValidator", "requestTracer", "modeDetector"
            ]
            
            tool_names = [tool["name"] for tool in tools]
            for expected in expected_tools:
                assert expected in tool_names, f"Missing tool: {expected}"
    
    # Echo Tools Tests
    
    @pytest.mark.asyncio
    async def test_echo_tool(self):
        """Test the echo tool."""
        async with MCPClient() as client:
            message = "Hello, MCP!"
            result = await client.call_tool("echo", {"message": message})
            
            # Result should contain the echoed message
            assert message in str(result)
            assert "Echo:" in str(result) or "echo" in str(result).lower()
    
    @pytest.mark.asyncio
    async def test_replay_last_echo(self):
        """Test the replayLastEcho tool."""
        async with MCPClient() as client:
            # First echo a message
            message = "Test message for replay"
            await client.call_tool("echo", {"message": message})
            
            # Then replay it
            result = await client.call_tool("replayLastEcho")
            
            # Should either replay the message or indicate stateless mode
            assert result is not None
            # In stateless mode, it will say not available
            # In stateful mode, it will replay the message
    
    # Debug Tools Tests
    
    @pytest.mark.asyncio
    async def test_print_header_tool(self):
        """Test the printHeader tool."""
        async with MCPClient() as client:
            result = await client.call_tool("printHeader", {
                "header_name": "Content-Type"
            })
            
            # Should return header info or not found
            assert result is not None
            # HTTP headers are case-insensitive, so check lowercase
            result_str = str(result)
            assert "content-type" in result_str.lower() or "not found" in result_str.lower()
    
    @pytest.mark.asyncio
    async def test_request_timing_tool(self):
        """Test the requestTiming tool."""
        async with MCPClient() as client:
            result = await client.call_tool("requestTiming")
            
            # Should return timing information or indicate no data
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_cors_analysis_tool(self):
        """Test the corsAnalysis tool."""
        async with MCPClient() as client:
            result = await client.call_tool("corsAnalysis")
            
            # Should return CORS analysis
            assert result is not None
            # Result should be JSON-like with CORS info
    
    @pytest.mark.asyncio
    async def test_environment_dump_tool(self):
        """Test the environmentDump tool."""
        async with MCPClient() as client:
            result = await client.call_tool("environmentDump", {
                "include_all": False
            })
            
            # Should return environment information
            assert result is not None
    
    # Auth Tools Tests
    
    @pytest.mark.asyncio
    async def test_bearer_decode_tool(self):
        """Test the bearerDecode tool."""
        async with MCPClient() as client:
            # Test with a sample JWT (not valid, just for testing structure)
            sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            
            result = await client.call_tool("bearerDecode", {
                "token": sample_jwt
            })
            
            # Should decode the token or return error
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_auth_context_tool(self):
        """Test the authContext tool."""
        async with MCPClient() as client:
            result = await client.call_tool("authContext")
            
            # Should return auth context
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_who_is_the_goat_tool(self):
        """Test the whoIStheGOAT easter egg tool."""
        async with MCPClient() as client:
            result = await client.call_tool("whoIStheGOAT")
            
            # Should return a fun message
            assert result is not None
            assert "GOAT" in str(result)
    
    # System Tools Tests
    
    @pytest.mark.asyncio
    async def test_health_probe_tool(self):
        """Test the healthProbe tool."""
        async with MCPClient() as client:
            result = await client.call_tool("healthProbe")
            
            # Should return health status
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_session_info_tool(self):
        """Test the sessionInfo tool."""
        async with MCPClient() as client:
            result = await client.call_tool("sessionInfo", {
                "session_id": client.session_id
            })
            
            # Should return session information
            assert result is not None
    
    # State Tools Tests
    
    @pytest.mark.asyncio
    async def test_state_inspector_tool(self):
        """Test the stateInspector tool."""
        async with MCPClient() as client:
            # Set some state first
            await client.call_tool("echo", {"message": "test state"})
            
            result = await client.call_tool("stateInspector", {
                "session_id": client.session_id
            })
            
            # Should return state information
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_session_history_tool(self):
        """Test the sessionHistory tool."""
        async with MCPClient() as client:
            # Create some history
            await client.call_tool("echo", {"message": "history entry 1"})
            await client.call_tool("echo", {"message": "history entry 2"})
            
            result = await client.call_tool("sessionHistory", {
                "session_id": client.session_id,
                "limit": 5
            })
            
            # Should return history or indicate stateless mode
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_state_manipulator_tool(self):
        """Test the stateManipulator tool."""
        async with MCPClient() as client:
            # Set a value
            result = await client.call_tool("stateManipulator", {
                "session_id": client.session_id,
                "operation": "set",
                "key": "test_key",
                "value": "test_value"
            })
            
            assert result is not None
            
            # Get the value
            result = await client.call_tool("stateManipulator", {
                "session_id": client.session_id,
                "operation": "get",
                "key": "test_key"
            })
            
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_session_compare_tool(self):
        """Test the sessionCompare tool."""
        async with MCPClient() as client:
            session1 = client.session_id
            
            # Create another session
            async with MCPClient() as client2:
                session2 = client2.session_id
                
                # Set different state in each session
                await client.call_tool("stateManipulator", {
                    "session_id": session1,
                    "operation": "set",
                    "key": "key1",
                    "value": "value1"
                })
                
                await client2.call_tool("stateManipulator", {
                    "session_id": session2,
                    "operation": "set",
                    "key": "key2",
                    "value": "value2"
                })
                
                # Compare sessions
                result = await client.call_tool("sessionCompare", {
                    "session_id1": session1,
                    "session_id2": session2
                })
                
                assert result is not None
    
    @pytest.mark.asyncio
    async def test_session_transfer_tool(self):
        """Test the sessionTransfer tool."""
        async with MCPClient() as client:
            source_session = client.session_id
            target_session = f"target_{uuid.uuid4()}"
            
            # Set some state
            await client.call_tool("stateManipulator", {
                "session_id": source_session,
                "operation": "set",
                "key": "transfer_test",
                "value": "data_to_transfer"
            })
            
            # Transfer state
            result = await client.call_tool("sessionTransfer", {
                "source_session": source_session,
                "target_session": target_session
            })
            
            # Should return transfer result or indicate stateless mode
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_state_benchmark_tool(self):
        """Test the stateBenchmark tool."""
        async with MCPClient() as client:
            result = await client.call_tool("stateBenchmark", {
                "operations": 10,  # Small number for testing
                "data_size": "small"
            })
            
            # Should return benchmark results
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_session_lifecycle_tool(self):
        """Test the sessionLifecycle tool."""
        async with MCPClient() as client:
            test_session = f"lifecycle_test_{uuid.uuid4()}"
            
            # Create session
            result = await client.call_tool("sessionLifecycle", {
                "session_id": test_session,
                "action": "create"
            })
            
            assert result is not None
            
            # Delete session
            result = await client.call_tool("sessionLifecycle", {
                "session_id": test_session,
                "action": "delete"
            })
            
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_state_validator_tool(self):
        """Test the stateValidator tool."""
        async with MCPClient() as client:
            # Set some state
            await client.call_tool("stateManipulator", {
                "session_id": client.session_id,
                "operation": "set",
                "key": "name",
                "value": "John Doe"
            })
            
            await client.call_tool("stateManipulator", {
                "session_id": client.session_id,
                "operation": "set",
                "key": "age",
                "value": 30
            })
            
            # Validate against schema
            result = await client.call_tool("stateValidator", {
                "session_id": client.session_id,
                "schema": {
                    "name": "string",
                    "age": "number",
                    "email": "string"  # This will be missing
                }
            })
            
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_request_tracer_tool(self):
        """Test the requestTracer tool."""
        async with MCPClient() as client:
            # Start a new trace
            result = await client.call_tool("requestTracer")
            
            # Should return trace information
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_mode_detector_tool(self):
        """Test the modeDetector tool."""
        async with MCPClient() as client:
            result = await client.call_tool("modeDetector")
            
            # Should return mode information
            assert result is not None
            # Should indicate current mode (stateful or stateless)


class TestMCPIntegration:
    """Integration tests for MCP with oauth-https-proxy."""
    
    @pytest.mark.asyncio
    async def test_full_tool_workflow(self):
        """Test a complete workflow using multiple tools."""
        async with MCPClient() as client:
            # 1. Check server health
            health = await client.call_tool("healthProbe")
            assert health is not None
            
            # 2. Get mode information
            mode = await client.call_tool("modeDetector")
            assert mode is not None
            
            # 3. Echo some messages
            echo1 = await client.call_tool("echo", {"message": "First message"})
            echo2 = await client.call_tool("echo", {"message": "Second message"})
            
            # 4. Inspect state
            state = await client.call_tool("stateInspector", {
                "session_id": client.session_id
            })
            
            # 5. Get session info
            session = await client.call_tool("sessionInfo", {
                "session_id": client.session_id
            })
            
            # All tools should work
            assert all([health, mode, echo1, echo2, state, session])
    
    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling for invalid tool calls."""
        async with MCPClient() as client:
            # Try to call non-existent tool
            with pytest.raises(Exception) as exc_info:
                await client.call_tool("nonExistentTool")
            
            # Should get method not found error
            assert "not found" in str(exc_info.value).lower() or "-32601" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_concurrent_sessions(self):
        """Test multiple concurrent sessions."""
        async def session_workflow(session_name: str):
            """Run a workflow in a session."""
            async with MCPClient() as client:
                # Echo with session identifier
                result = await client.call_tool("echo", {
                    "message": f"Hello from {session_name}"
                })
                
                # Set some state
                await client.call_tool("stateManipulator", {
                    "session_id": client.session_id,
                    "operation": "set",
                    "key": "session_name",
                    "value": session_name
                })
                
                return client.session_id, result
        
        # Run multiple sessions concurrently
        results = await asyncio.gather(
            session_workflow("Session1"),
            session_workflow("Session2"),
            session_workflow("Session3")
        )
        
        # All sessions should complete successfully
        assert len(results) == 3
        # Each should have unique session ID
        session_ids = [r[0] for r in results]
        assert len(set(session_ids)) == 3


# Performance test (optional, can be slow)
@pytest.mark.slow
@pytest.mark.asyncio
async def test_mcp_performance():
    """Test MCP server performance with multiple rapid requests."""
    async with MCPClient() as client:
        start_time = time.time()
        num_requests = 100
        
        # Make many rapid echo requests
        tasks = []
        for i in range(num_requests):
            task = client.call_tool("echo", {
                "message": f"Performance test {i}"
            })
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        elapsed = time.time() - start_time
        requests_per_second = num_requests / elapsed
        
        logger.info(f"Completed {num_requests} requests in {elapsed:.2f}s")
        logger.info(f"Rate: {requests_per_second:.2f} requests/second")
        
        # All requests should succeed
        assert len(results) == num_requests
        assert all(r is not None for r in results)
        
        # Should handle at least 10 requests per second
        assert requests_per_second > 10


if __name__ == "__main__":
    # Run the tests
    import sys
    pytest.main([__file__, "-v", "-s"] + sys.argv[1:])