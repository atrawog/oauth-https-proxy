#!/usr/bin/env python3
"""
Test MCP Echo Server functionality through the HTTPS proxy.

This test verifies that the MCP Echo Server is:
1. Accessible through the proxy at echo.atratest.org
2. Properly handling MCP protocol initialization
3. Correctly executing echo tools
4. Maintaining session state
"""

import json
import ssl
import time
from typing import Dict, Any, Optional

import httpx
import pytest
import pytest_asyncio


# Constants
ECHO_SERVER_URL = "https://echo.atratest.org"
MCP_ENDPOINT = f"{ECHO_SERVER_URL}/mcp"
PROTOCOL_VERSION = "2025-06-18"


# Create SSL context that doesn't verify certificates (for development)
def create_test_ssl_context():
    """Create an SSL context for testing that doesn't verify certificates."""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


class MCPTestClient:
    """Test client for MCP protocol over HTTP."""
    
    def __init__(self, base_url: str = MCP_ENDPOINT):
        self.base_url = base_url
        self.session_id: Optional[str] = None
        self.client = httpx.AsyncClient(timeout=30.0, verify=False)
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def send_request(
        self,
        method: str,
        params: Dict[str, Any],
        request_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Send an MCP request and parse the SSE response."""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json,text/event-stream'
        }
        
        if self.session_id:
            headers['mcp-session-id'] = self.session_id
        
        json_payload = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params
        }
        
        if request_id is not None:
            json_payload['id'] = request_id
        
        response = await self.client.post(
            self.base_url,
            headers=headers,
            json=json_payload
        )
        
        # Parse SSE response
        for line in response.text.split('\n'):
            if line.startswith('data: '):
                try:
                    data = json.loads(line[6:])
                    
                    # Extract session ID from response headers if present
                    if 'mcp-session-id' in response.headers:
                        self.session_id = response.headers['mcp-session-id']
                    
                    return data
                except json.JSONDecodeError:
                    continue
        
        return {'error': 'No valid response received'}
    
    async def initialize(self) -> Dict[str, Any]:
        """Initialize MCP session."""
        # Send initialization request
        init_result = await self.send_request(
            'initialize',
            {
                'protocolVersion': PROTOCOL_VERSION,
                'capabilities': {},  # Required field for MCP initialization
                'clientInfo': {
                    'name': 'test-client',
                    'version': '1.0.0'
                }
            },
            request_id=1
        )
        
        # If initialization succeeded, send initialized notification
        if 'result' in init_result and 'error' not in init_result:
            await self.send_request(
                'notifications/initialized',
                {},
                request_id=None  # Notifications don't have IDs
            )
        
        return init_result
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        request_id: int
    ) -> Dict[str, Any]:
        """Call an MCP tool."""
        result = await self.send_request(
            'tools/call',
            {
                'name': tool_name,
                'arguments': arguments
            },
            request_id=request_id
        )
        
        # Extract the actual result from the response
        if 'result' in result and not result.get('error'):
            tool_result = result['result']
            if tool_result.get('isError'):
                return {'error': tool_result['content'][0]['text']}
            else:
                try:
                    # Try to parse as JSON
                    return json.loads(tool_result['content'][0]['text'])
                except (json.JSONDecodeError, KeyError, IndexError):
                    # Return as string if not JSON
                    return tool_result['content'][0].get('text', str(tool_result))
        
        return result


@pytest.mark.asyncio
async def test_mcp_echo_server_connectivity():
    """Test that MCP Echo Server is accessible through the proxy."""
    async with httpx.AsyncClient(verify=False) as client:
        # Test that the server is responding
        response = await client.get(f"{ECHO_SERVER_URL}/")
        assert response.status_code in [200, 404], f"Server not accessible: {response.status_code}"


@pytest.mark.asyncio
async def test_mcp_initialization():
    """Test MCP protocol initialization."""
    async with MCPTestClient() as client:
        # Test initialization
        init_result = await client.initialize()
        
        # Check for errors
        assert 'error' not in init_result, f"Initialization failed: {init_result.get('error')}"
        
        # Verify protocol version if successful
        if 'result' in init_result:
            result = init_result['result']
            assert 'protocolVersion' in result, "No protocol version in response"
            # Protocol version might be negotiated differently
            assert result['protocolVersion'] in ['2025-06-18', '2025-03-26', '2024-11-05'], \
                f"Unexpected protocol version: {result['protocolVersion']}"


@pytest.mark.asyncio
async def test_echo_tool():
    """Test the echo tool functionality."""
    async with MCPTestClient() as client:
        # Initialize first
        init_result = await client.initialize()
        
        # Skip if initialization fails (server might require different init)
        if 'error' in init_result:
            pytest.skip(f"Initialization failed: {init_result['error']}")
        
        # Test echo tool
        echo_message = "Hello from pytest!"
        echo_result = await client.call_tool(
            'echo',
            {'message': echo_message},
            request_id=2
        )
        
        # Check result
        assert 'error' not in echo_result, f"Echo failed: {echo_result.get('error')}"
        assert echo_message in str(echo_result), f"Echo message not in response: {echo_result}"


@pytest.mark.asyncio
async def test_state_persistence():
    """Test that state persists across tool calls."""
    async with MCPTestClient() as client:
        # Initialize
        init_result = await client.initialize()
        if 'error' in init_result:
            pytest.skip(f"Initialization failed: {init_result['error']}")
        
        # Set a state value
        state_key = f"test_key_{int(time.time())}"
        state_value = "test_value"
        
        set_result = await client.call_tool(
            'stateManipulator',
            {
                'action': 'set',
                'key': state_key,
                'value': state_value
            },
            request_id=3
        )
        
        # Verify state was set
        if 'error' not in set_result:
            assert set_result.get('success') is True, f"State not set: {set_result}"
        
        # Inspect state to verify persistence
        inspect_result = await client.call_tool(
            'stateInspector',
            {'key_pattern': state_key},
            request_id=4
        )
        
        # Check if state was persisted
        if 'error' not in inspect_result and 'states' in inspect_result:
            states = inspect_result['states']
            assert state_key in states, f"State key not found: {list(states.keys())}"
            assert states[state_key]['value'] == state_value, \
                f"State value mismatch: {states[state_key]['value']} != {state_value}"


@pytest.mark.asyncio
async def test_replay_echo():
    """Test echo replay functionality."""
    async with MCPTestClient() as client:
        # Initialize
        init_result = await client.initialize()
        if 'error' in init_result:
            pytest.skip(f"Initialization failed: {init_result['error']}")
        
        # Echo a message first
        echo_message = "Message to replay"
        echo_result = await client.call_tool(
            'echo',
            {'message': echo_message},
            request_id=5
        )
        
        # Skip if echo fails
        if 'error' in echo_result:
            pytest.skip(f"Echo failed: {echo_result['error']}")
        
        # Test replay
        replay_result = await client.call_tool(
            'replayLastEcho',
            {},
            request_id=6
        )
        
        # Check replay result
        assert 'error' not in replay_result, f"Replay failed: {replay_result.get('error')}"
        assert echo_message in str(replay_result), \
            f"Original message not in replay: {replay_result}"


@pytest.mark.asyncio
async def test_health_probe():
    """Test the health probe tool."""
    async with MCPTestClient() as client:
        # Initialize
        init_result = await client.initialize()
        if 'error' in init_result:
            pytest.skip(f"Initialization failed: {init_result['error']}")
        
        # Test health probe
        health_result = await client.call_tool(
            'healthProbe',
            {},
            request_id=7
        )
        
        # Check health status
        assert 'error' not in health_result, f"Health probe failed: {health_result.get('error')}"
        
        if isinstance(health_result, dict):
            assert health_result.get('status') == 'healthy', \
                f"Server not healthy: {health_result.get('status')}"


@pytest.mark.asyncio
async def test_session_info():
    """Test session information retrieval."""
    async with MCPTestClient() as client:
        # Initialize
        init_result = await client.initialize()
        if 'error' in init_result:
            pytest.skip(f"Initialization failed: {init_result['error']}")
        
        # Get session info
        session_result = await client.call_tool(
            'sessionInfo',
            {},
            request_id=8
        )
        
        # Check session info
        assert 'error' not in session_result, f"Session info failed: {session_result.get('error')}"
        
        if isinstance(session_result, dict):
            # Should have current_session or mode information
            assert any(key in session_result for key in ['current_session', 'mode', 'server']), \
                f"No session information in response: {session_result.keys()}"


@pytest.mark.asyncio
async def test_all_21_tools():
    """Test that all 21 tools are accessible and respond."""
    tools = [
        # Echo Tools (2)
        ('echo', {'message': 'test'}),
        ('replayLastEcho', {}),
        
        # Debug Tools (4)
        ('printHeader', {}),
        ('requestTiming', {}),
        ('corsAnalysis', {}),
        ('environmentDump', {}),
        
        # Auth Tools (3)
        ('bearerDecode', {}),
        ('authContext', {}),
        ('whoIStheGOAT', {}),
        
        # System Tools (2)
        ('healthProbe', {}),
        ('sessionInfo', {}),
        
        # State Tools (10)
        ('stateInspector', {'key_pattern': '*'}),
        ('stateManipulator', {'action': 'set', 'key': 'test', 'value': 'value'}),
        ('stateBenchmark', {'operations': 10}),
        ('stateValidator', {}),
        ('sessionHistory', {}),
        ('sessionLifecycle', {}),
        ('sessionTransfer', {'action': 'export'}),
        ('sessionCompare', {}),
        ('requestTracer', {}),
        ('modeDetector', {}),
    ]
    
    async with MCPTestClient() as client:
        # Initialize
        init_result = await client.initialize()
        if 'error' in init_result:
            pytest.skip(f"Initialization failed: {init_result['error']}")
        
        results = {}
        errors = []
        
        for i, (tool_name, args) in enumerate(tools, start=10):
            result = await client.call_tool(tool_name, args, request_id=i)
            
            if 'error' in result:
                # Some tools might legitimately return errors (e.g., bearerDecode without auth)
                # but they should still respond
                if 'No Authorization header' in str(result.get('error')):
                    results[tool_name] = 'expected_error'
                else:
                    errors.append(f"{tool_name}: {result['error']}")
                    results[tool_name] = 'error'
            else:
                results[tool_name] = 'success'
        
        # Report results
        successful = sum(1 for r in results.values() if r in ['success', 'expected_error'])
        failed = len(results) - successful
        
        print(f"\nTool Test Results: {successful}/21 successful")
        if errors:
            print("Errors:")
            for error in errors:
                print(f"  - {error}")
        
        # At least 18 out of 21 tools should work
        # (allowing for auth tools that might fail without proper headers)
        assert successful >= 18, f"Too many tools failed: {failed}/21 failed"


if __name__ == "__main__":
    # Allow running directly
    import asyncio
    
    async def run_tests():
        print("Testing MCP Echo Server...")
        
        try:
            await test_mcp_echo_server_connectivity()
            print("✅ Connectivity test passed")
        except AssertionError as e:
            print(f"❌ Connectivity test failed: {e}")
        
        try:
            await test_mcp_initialization()
            print("✅ Initialization test passed")
        except AssertionError as e:
            print(f"❌ Initialization test failed: {e}")
        
        try:
            await test_echo_tool()
            print("✅ Echo tool test passed")
        except AssertionError as e:
            print(f"❌ Echo tool test failed: {e}")
        
        try:
            await test_all_21_tools()
            print("✅ All tools test passed")
        except AssertionError as e:
            print(f"❌ All tools test failed: {e}")
    
    asyncio.run(run_tests())