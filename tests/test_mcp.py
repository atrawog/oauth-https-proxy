"""Basic MCP functionality tests.

This test suite verifies basic MCP server functionality including:
- MCP module imports
- FastMCP server creation
- Tool registration
- Session management basics
"""

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_mcp_sdk_import():
    """Test that MCP SDK can be imported."""
    try:
        from mcp.server.fastmcp import FastMCP
        assert FastMCP is not None
    except ImportError:
        pytest.skip("MCP SDK not installed")


def test_fastmcp_server_creation():
    """Test creating a FastMCP server instance."""
    from mcp.server.fastmcp import FastMCP
    
    server = FastMCP("test-server")
    assert server is not None
    assert hasattr(server, 'tool')
    # FastMCP implementation may vary, just check it's created


def test_mcp_router_imports():
    """Test that MCP router modules can be imported."""
    # These imports should not raise exceptions
    from src.api.routers.mcp import (
        mount_mcp_app,
        MCPEventPublisher,
        IntegratedMCPServer,
        MCPSessionManager
    )
    
    assert mount_mcp_app is not None
    assert MCPEventPublisher is not None
    assert IntegratedMCPServer is not None
    assert MCPSessionManager is not None


def test_tool_registration():
    """Test registering tools with FastMCP."""
    from mcp.server.fastmcp import FastMCP
    
    server = FastMCP("test-server")
    
    # Register a simple tool
    @server.tool()
    def test_tool(message: str) -> str:
        """Test tool that echoes a message."""
        return f"Echo: {message}"
    
    # Verify tool is registered
    # Note: Actual tool verification would require accessing internal server state
    # FastMCP implementation details may vary


@pytest.mark.asyncio
async def test_session_manager_basic():
    """Test basic session manager functionality."""
    from src.api.routers.mcp.session_manager import MCPSessionManager
    
    # Create mocks
    mock_storage = MagicMock()
    mock_storage.redis_client = AsyncMock()
    mock_logger = MagicMock()
    mock_logger.set_component = MagicMock()
    mock_logger.trace_context = MagicMock()
    mock_logger.event = AsyncMock()
    
    # Create a mock async context manager
    class MockTraceContext:
        async def __aenter__(self):
            return "trace-123"
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
    
    mock_logger.trace_context.return_value = MockTraceContext()
    
    # Create session manager
    session_manager = MCPSessionManager(mock_storage, mock_logger)
    
    # Test session ID generation
    session_id = session_manager.generate_session_id()
    assert session_id.startswith("mcp-")
    assert len(session_id) > 10
    
    # Test session creation (mocked)
    mock_storage.redis_client.hset = AsyncMock()
    mock_storage.redis_client.expire = AsyncMock()
    mock_storage.redis_client.zadd = AsyncMock()
    mock_storage.redis_client.xadd = AsyncMock()
    
    client_info = {"ip": "127.0.0.1", "user_agent": "test-client"}
    created_id = await session_manager.create_session(client_info)
    
    assert created_id.startswith("mcp-")
    mock_storage.redis_client.hset.assert_called()
    mock_storage.redis_client.expire.assert_called()


@pytest.mark.asyncio
async def test_event_publisher_basic():
    """Test basic event publisher functionality."""
    from src.api.routers.mcp.event_publisher import MCPEventPublisher
    
    # Create mocks
    mock_storage = MagicMock()
    mock_storage.redis_client = AsyncMock()
    mock_logger = MagicMock()
    mock_logger.set_component = MagicMock()
    mock_logger.debug = AsyncMock()
    
    # Create event publisher
    event_publisher = MCPEventPublisher(mock_storage, mock_logger)
    
    # Test workflow event publishing
    mock_storage.redis_client.xadd = AsyncMock(return_value="event-123")
    
    event_id = await event_publisher.publish_workflow_event(
        event_type="test_event",
        hostname="test.example.com",
        data={"test": "data"},
        trace_id="trace-123"
    )
    
    assert event_id == "event-123"
    mock_storage.redis_client.xadd.assert_called_once()
    
    # Verify the event data structure
    call_args = mock_storage.redis_client.xadd.call_args
    assert call_args[0][0] == "events:workflow"
    event_data = call_args[0][1]
    assert event_data["event_type"] == "test_event"
    assert event_data["hostname"] == "test.example.com"
    assert event_data["source"] == "mcp"


@pytest.mark.asyncio
async def test_mcp_server_initialization():
    """Test IntegratedMCPServer initialization."""
    from src.api.routers.mcp.mcp_server import IntegratedMCPServer
    
    # Create mocks
    mock_storage = MagicMock()
    mock_storage.redis_client = AsyncMock()
    mock_logger = MagicMock()
    mock_logger.set_component = MagicMock()
    
    # Create MCP server
    server = IntegratedMCPServer(
        mock_storage,
        mock_logger,
        cert_manager=None,
        docker_manager=None
    )
    
    assert server.mcp is not None
    assert server.storage == mock_storage
    assert server.logger == mock_logger
    assert server.session_manager is not None
    assert server.event_publisher is not None
    
    # Get the FastMCP instance
    mcp = server.get_server()
    assert mcp is not None


def test_mcp_tools_defined():
    """Test that expected MCP tools are defined."""
    from mcp.server.fastmcp import FastMCP
    from src.api.routers.mcp.mcp_server import IntegratedMCPServer
    
    # Create mocks
    mock_storage = MagicMock()
    mock_storage.redis_client = AsyncMock()
    mock_logger = MagicMock()
    mock_logger.set_component = MagicMock()
    mock_logger.trace_context = MagicMock()
    
    # Create server
    server = IntegratedMCPServer(
        mock_storage,
        mock_logger,
        cert_manager=None,
        docker_manager=None
    )
    
    # The tools should be registered in the server
    # This is a basic check - actual tool functionality is tested via integration tests
    assert server.mcp is not None
    assert isinstance(server.mcp, FastMCP)


@pytest.mark.asyncio
async def test_mcp_router_creation():
    """Test creating the MCP FastAPI router."""
    from src.api.routers.mcp.mcp_fastapi import create_mcp_router
    from fastapi import APIRouter
    
    # Create mock storage
    mock_storage = MagicMock()
    mock_storage.redis_client = AsyncMock()
    
    # Create mock logger
    mock_logger = MagicMock()
    mock_logger.set_component = MagicMock()
    
    # Create router
    router = create_mcp_router(
        mock_storage,
        cert_manager=None,
        docker_manager=None,
        unified_logger=mock_logger
    )
    
    assert router is not None
    assert isinstance(router, APIRouter)
    
    # Check that routes are defined
    routes = [route.path for route in router.routes]
    assert "" in routes or "/" in routes  # Main MCP endpoint


def test_session_id_format():
    """Test that session IDs have the correct format."""
    from src.api.routers.mcp.session_manager import MCPSessionManager
    
    # Create mocks
    mock_storage = MagicMock()
    mock_storage.redis_client = AsyncMock()
    mock_logger = MagicMock()
    mock_logger.set_component = MagicMock()
    
    manager = MCPSessionManager(mock_storage, mock_logger)
    
    # Generate multiple session IDs and verify format
    for _ in range(10):
        session_id = manager.generate_session_id()
        assert session_id.startswith("mcp-")
        assert len(session_id) == 36  # "mcp-" + 32 hex chars
        assert all(c in "0123456789abcdef-" for c in session_id[4:])


def test_redis_key_patterns():
    """Test that Redis keys follow expected patterns."""
    from src.api.routers.mcp.session_manager import MCPSessionManager
    
    # Verify key patterns
    assert MCPSessionManager.SESSION_PREFIX == "mcp:session:"
    assert MCPSessionManager.SESSION_INDEX == "mcp:session:index:active"
    assert MCPSessionManager.SESSION_TTL == 3600


@pytest.mark.asyncio
async def test_audit_event_structure():
    """Test audit event data structure."""
    from src.api.routers.mcp.event_publisher import MCPEventPublisher
    
    # Create mocks
    mock_storage = MagicMock()
    mock_storage.redis_client = AsyncMock()
    mock_storage.redis_client.xadd = AsyncMock(return_value="audit-123")
    mock_storage.redis_client.zadd = AsyncMock()
    mock_storage.redis_client.expire = AsyncMock()
    mock_logger = MagicMock()
    mock_logger.set_component = MagicMock()
    
    publisher = MCPEventPublisher(mock_storage, mock_logger)
    
    # Publish audit event
    event_id = await publisher.publish_audit_event(
        action="test_action",
        session_id="mcp-test123",
        user="testuser",
        details={"key": "value"}
    )
    
    assert event_id == "audit-123"
    
    # Verify the audit event was published to the correct stream
    call_args = mock_storage.redis_client.xadd.call_args
    assert call_args[0][0] == "stream:audit:mcp"
    
    # Verify event data
    event_data = call_args[0][1]
    assert event_data["action"] == "test_action"
    assert event_data["user"] == "testuser"
    assert event_data["source"] == "mcp"
    assert event_data["session_id"] == "mcp-test123"
    assert "timestamp" in event_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])