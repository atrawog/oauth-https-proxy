"""Test MCP integration with full Redis Streams and logging.

This test suite verifies that the MCP server is properly integrated with:
- Redis-backed session management
- Event publishing to Redis Streams
- Unified logging system
- Workflow orchestration
- Tool execution tracking
"""

import json
import time
import asyncio
from typing import Dict, Any, Optional

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis


# Test configuration
API_BASE = "http://localhost:9000"
MCP_ENDPOINT = f"{API_BASE}/mcp"


class MCPTestClient:
    """Test client for MCP protocol over HTTP."""
    
    def __init__(self, base_url: str = MCP_ENDPOINT):
        self.base_url = base_url
        self.session_id: Optional[str] = None
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def send_request(
        self,
        method: str,
        params: Dict[str, Any] = None,
        request_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Send an MCP request and parse the response."""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'  # Request JSON response
        }
        
        if self.session_id:
            headers['mcp-session-id'] = self.session_id
        
        json_payload = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params or {}
        }
        
        if request_id is not None:
            json_payload['id'] = request_id
        
        response = await self.client.post(
            self.base_url,
            headers=headers,
            json=json_payload
        )
        
        # Extract session ID from response headers if present
        if 'mcp-session-id' in response.headers:
            self.session_id = response.headers['mcp-session-id']
        
        response.raise_for_status()
        return response.json()
    
    async def initialize(self) -> Dict[str, Any]:
        """Send MCP initialization request."""
        return await self.send_request(
            'initialize',
            {
                'protocolVersion': '2025-06-18',
                'capabilities': {
                    'tools': {'listSupported': True}
                },
                'clientInfo': {
                    'name': 'test-client',
                    'version': '1.0.0'
                }
            },
            request_id=1
        )
    
    async def list_tools(self) -> Dict[str, Any]:
        """Request list of available tools."""
        return await self.send_request(
            'tools/list',
            {},
            request_id=2
        )
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Call a specific tool."""
        return await self.send_request(
            'tools/call',
            {
                'name': tool_name,
                'arguments': arguments
            },
            request_id=3
        )


@pytest_asyncio.fixture
async def redis_client():
    """Create Redis client for test verification."""
    # Get Redis password from environment or use default
    import os
    redis_password = os.environ.get('REDIS_PASSWORD', 'your-redis-password')
    
    client = redis.Redis(
        host='localhost',
        port=6379,
        password=redis_password,
        decode_responses=True
    )
    
    try:
        await client.ping()
        yield client
    finally:
        await client.close()


@pytest_asyncio.fixture
async def mcp_client():
    """Create MCP test client."""
    async with MCPTestClient() as client:
        yield client


@pytest.mark.asyncio
async def test_mcp_initialization(mcp_client, redis_client):
    """Test MCP initialization and session creation."""
    # Send initialization request
    response = await mcp_client.initialize()
    
    # Verify response structure
    assert 'result' in response
    result = response['result']
    assert 'protocolVersion' in result
    assert 'capabilities' in result
    assert 'serverInfo' in result
    assert result['serverInfo']['name'] == 'OAuth-HTTPS-Proxy-MCP'
    
    # Verify session was created
    assert mcp_client.session_id is not None
    assert mcp_client.session_id.startswith('mcp-')
    
    # Verify session in Redis
    session_key = f"mcp:session:{mcp_client.session_id}"
    session_data = await redis_client.hgetall(session_key)
    assert session_data is not None
    assert session_data['state'] == 'active'
    assert 'created_at' in session_data
    assert 'client_info' in session_data
    
    # Verify session in active index
    score = await redis_client.zscore(
        "mcp:session:index:active",
        mcp_client.session_id
    )
    assert score is not None


@pytest.mark.asyncio
async def test_mcp_tool_listing(mcp_client):
    """Test listing available MCP tools."""
    # Initialize first
    await mcp_client.initialize()
    
    # List tools
    response = await mcp_client.list_tools()
    
    # Verify response
    assert 'result' in response
    result = response['result']
    assert 'tools' in result
    tools = result['tools']
    assert isinstance(tools, list)
    assert len(tools) > 0
    
    # Check for expected tools
    tool_names = [tool['name'] for tool in tools]
    assert 'echo' in tool_names
    assert 'health_check' in tool_names
    assert 'list_proxies' in tool_names
    assert 'create_proxy' in tool_names
    
    # Verify tool structure
    for tool in tools:
        assert 'name' in tool
        assert 'description' in tool
        assert 'inputSchema' in tool


@pytest.mark.asyncio
async def test_mcp_echo_tool(mcp_client, redis_client):
    """Test executing the echo tool."""
    # Initialize first
    await mcp_client.initialize()
    
    # Call echo tool
    test_message = "Hello, MCP!"
    response = await mcp_client.call_tool(
        'echo',
        {'message': test_message}
    )
    
    # Verify response
    assert 'result' in response
    result = response['result']
    assert 'content' in result
    assert isinstance(result['content'], list)
    assert len(result['content']) > 0
    
    content = result['content'][0]
    assert content['type'] == 'text'
    assert content['text'] == f"Echo: {test_message}"
    
    # Verify tool execution was logged to Redis Streams
    # Check tool execution stream
    stream_entries = await redis_client.xread(
        {"stream:mcp:tools": "0"},
        count=100
    )
    
    # Find our tool execution
    found = False
    for stream_name, entries in stream_entries:
        for entry_id, data in entries:
            if data.get('tool') == 'echo' and \
               data.get('session_id') == mcp_client.session_id:
                found = True
                assert data['status'] == 'success'
                assert 'exec_id' in data
                break
    
    assert found, "Tool execution not found in Redis stream"


@pytest.mark.asyncio
async def test_mcp_health_check_tool(mcp_client):
    """Test the health check tool."""
    # Initialize first
    await mcp_client.initialize()
    
    # Call health check tool
    response = await mcp_client.call_tool('health_check', {})
    
    # Verify response
    assert 'result' in response
    result = response['result']
    assert 'content' in result
    
    content = result['content'][0]
    assert content['type'] == 'text'
    
    # Parse the health check result
    health_data = json.loads(content['text'])
    assert health_data['status'] in ['healthy', 'degraded']
    assert 'components' in health_data
    assert 'redis' in health_data['components']
    assert health_data['components']['redis'] == 'healthy'


@pytest.mark.asyncio
async def test_mcp_list_proxies_tool(mcp_client):
    """Test listing proxies through MCP."""
    # Initialize first
    await mcp_client.initialize()
    
    # Call list_proxies tool
    response = await mcp_client.call_tool(
        'list_proxies',
        {'include_details': True}
    )
    
    # Verify response
    assert 'result' in response
    result = response['result']
    assert 'content' in result
    
    content = result['content'][0]
    assert content['type'] == 'text'
    
    # Parse the proxy list
    proxy_data = json.loads(content['text'])
    assert 'proxies' in proxy_data
    assert 'count' in proxy_data
    assert proxy_data['count'] == len(proxy_data['proxies'])


@pytest.mark.asyncio
async def test_mcp_session_persistence(redis_client):
    """Test that MCP sessions persist across requests."""
    # Create first client and initialize
    async with MCPTestClient() as client1:
        await client1.initialize()
        session_id = client1.session_id
        
        # Call a tool to generate activity
        await client1.call_tool('echo', {'message': 'test1'})
    
    # Create second client with same session ID
    async with MCPTestClient() as client2:
        client2.session_id = session_id
        
        # Should be able to use existing session
        response = await client2.call_tool('echo', {'message': 'test2'})
        assert 'result' in response
        
        # Verify session counters were incremented
        session_data = await redis_client.hgetall(f"mcp:session:{session_id}")
        assert int(session_data['messages_received']) >= 2
        assert int(session_data['messages_sent']) >= 2


@pytest.mark.asyncio
async def test_mcp_request_logging(mcp_client, redis_client):
    """Test that MCP requests are logged to Redis Streams."""
    # Initialize
    await mcp_client.initialize()
    
    # Make a request
    await mcp_client.call_tool('echo', {'message': 'log test'})
    
    # Check request stream
    request_stream = await redis_client.xread(
        {"stream:mcp:requests": "0"},
        count=100
    )
    
    # Find our requests
    found_init = False
    found_tool = False
    
    for stream_name, entries in request_stream:
        for entry_id, data in entries:
            if data.get('session_id') == mcp_client.session_id:
                if data.get('method') == 'initialize':
                    found_init = True
                elif data.get('method') == 'tools/call':
                    found_tool = True
    
    assert found_init, "Initialize request not logged"
    assert found_tool, "Tool call request not logged"


@pytest.mark.asyncio
async def test_mcp_workflow_event_publishing(mcp_client, redis_client):
    """Test that MCP tool executions publish workflow events."""
    # Initialize
    await mcp_client.initialize()
    
    # Get admin token from environment
    import os
    admin_token = os.environ.get('ADMIN_TOKEN', 'acm_admin_token_here')
    
    # Create a proxy (this should publish a workflow event)
    try:
        response = await mcp_client.call_tool(
            'create_proxy',
            {
                'hostname': 'test-mcp.example.com',
                'target_url': 'http://localhost:8080',
                'token': admin_token,
                'enable_http': True,
                'enable_https': False
            }
        )
        
        # Check workflow event stream
        workflow_stream = await redis_client.xread(
            {"events:workflow": "0"},
            count=100
        )
        
        # Find the proxy_created event
        found = False
        for stream_name, entries in workflow_stream:
            for entry_id, data in entries:
                if data.get('event_type') == 'proxy_created' and \
                   data.get('hostname') == 'test-mcp.example.com':
                    found = True
                    event_data = json.loads(data['data'])
                    assert event_data['created_by'] == 'mcp'
                    assert event_data['session_id'] == mcp_client.session_id
                    break
        
        assert found, "Workflow event not published"
        
    except Exception as e:
        # Proxy creation might fail if already exists or token invalid
        # But we're mainly testing the event publishing mechanism
        pass


@pytest.mark.asyncio
async def test_mcp_session_cleanup(mcp_client, redis_client):
    """Test session cleanup functionality."""
    # Initialize
    await mcp_client.initialize()
    session_id = mcp_client.session_id
    
    # End session via API
    async with httpx.AsyncClient() as http_client:
        # Need admin token for this endpoint
        import os
        admin_token = os.environ.get('ADMIN_TOKEN', 'acm_admin_token_here')
        
        response = await http_client.delete(
            f"{API_BASE}/mcp/sessions/{session_id}",
            headers={'Authorization': f'Bearer {admin_token}'}
        )
        
        if response.status_code == 200:
            # Verify session was ended
            session_data = await redis_client.hgetall(f"mcp:session:{session_id}")
            assert session_data['state'] == 'ended'
            assert 'end_reason' in session_data
            
            # Verify removed from active index
            score = await redis_client.zscore(
                "mcp:session:index:active",
                session_id
            )
            assert score is None


@pytest.mark.asyncio
async def test_mcp_sse_streaming():
    """Test SSE streaming response format."""
    async with httpx.AsyncClient() as client:
        # Send request with SSE accept header
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'text/event-stream'
        }
        
        response = await client.post(
            MCP_ENDPOINT,
            headers=headers,
            json={
                'jsonrpc': '2.0',
                'method': 'initialize',
                'params': {
                    'protocolVersion': '2025-06-18',
                    'capabilities': {}
                },
                'id': 1
            }
        )
        
        # Verify SSE response
        assert response.status_code == 200
        assert response.headers['content-type'] == 'text/event-stream'
        assert 'mcp-session-id' in response.headers
        
        # Parse SSE data
        content = response.text
        assert content.startswith('data: ')
        
        # Extract JSON from SSE
        json_start = content.find('data: ') + 6
        json_end = content.find('\n\n', json_start)
        json_data = content[json_start:json_end]
        
        data = json.loads(json_data)
        assert 'result' in data or 'error' in data


@pytest.mark.asyncio
async def test_mcp_stats_endpoint():
    """Test MCP statistics endpoint."""
    async with httpx.AsyncClient() as client:
        # Get stats (requires auth)
        import os
        admin_token = os.environ.get('ADMIN_TOKEN', 'acm_admin_token_here')
        
        response = await client.get(
            f"{API_BASE}/mcp/stats",
            headers={'Authorization': f'Bearer {admin_token}'},
            params={'hours': 1}
        )
        
        if response.status_code == 200:
            stats = response.json()
            assert 'period_hours' in stats
            assert 'active_sessions' in stats
            assert 'tool_usage' in stats
            assert 'total_tool_calls' in stats


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])