"""
Test suite for PROXY protocol v1 compliance.

Tests against HAProxy PROXY protocol specification:
https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
"""
import asyncio
import pytest
import redis
from unittest.mock import AsyncMock, MagicMock, patch

from src.middleware.proxy_protocol_handler_fixed import ProxyProtocolHandler


class MockStreamReader:
    """Mock asyncio StreamReader for testing."""
    
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0
    
    async def read(self, n: int) -> bytes:
        """Read up to n bytes."""
        result = self.data[self.position:self.position + n]
        self.position += len(result)
        return result
    
    async def readuntil(self, separator: bytes) -> bytes:
        """Read until separator is found."""
        sep_pos = self.data.find(separator, self.position)
        if sep_pos == -1:
            raise asyncio.IncompleteReadError(self.data[self.position:], separator)
        result = self.data[self.position:sep_pos + len(separator)]
        self.position = sep_pos + len(separator)
        return result


class MockStreamWriter:
    """Mock asyncio StreamWriter for testing."""
    
    def __init__(self):
        self.data = b''
        self.closed = False
        self._extra_info = {'peername': ('192.168.1.100', 54321)}
    
    def write(self, data: bytes):
        self.data += data
    
    async def drain(self):
        pass
    
    def close(self):
        self.closed = True
    
    async def wait_closed(self):
        pass
    
    def get_extra_info(self, name: str):
        return self._extra_info.get(name)


@pytest.mark.asyncio
class TestProxyProtocolCompliance:
    """Test PROXY protocol v1 compliance."""
    
    async def test_valid_tcp4_header(self):
        """Test valid TCP4 PROXY header."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Valid TCP4 header (56 chars max)
        data = b'PROXY TCP4 192.168.1.1 192.168.1.2 56324 443\r\nGET / HTTP/1.1\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        with patch('asyncio.open_connection') as mock_connect:
            backend_reader = AsyncMock()
            backend_writer = AsyncMock()
            backend_writer.get_extra_info.return_value = ('127.0.0.1', 12345)
            mock_connect.return_value = (backend_reader, backend_writer)
            
            # Patch _forward_data to avoid infinite loop
            with patch.object(handler, '_forward_data', new_callable=AsyncMock):
                await handler.handle_connection(reader, writer)
        
        # Verify connection was not closed (valid header)
        assert not writer.closed
    
    async def test_valid_tcp6_header(self):
        """Test valid TCP6 PROXY header."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Valid TCP6 header (104 chars max)
        data = b'PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\nGET / HTTP/1.1\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        with patch('asyncio.open_connection') as mock_connect:
            backend_reader = AsyncMock()
            backend_writer = AsyncMock()
            backend_writer.get_extra_info.return_value = ('127.0.0.1', 12345)
            mock_connect.return_value = (backend_reader, backend_writer)
            
            with patch.object(handler, '_forward_data', new_callable=AsyncMock):
                await handler.handle_connection(reader, writer)
        
        assert not writer.closed
    
    async def test_unknown_protocol(self):
        """Test UNKNOWN protocol support."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # UNKNOWN header (15 chars)
        data = b'PROXY UNKNOWN\r\nGET / HTTP/1.1\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        with patch('asyncio.open_connection') as mock_connect:
            backend_reader = AsyncMock()
            backend_writer = AsyncMock()
            backend_writer.get_extra_info.return_value = ('127.0.0.1', 12345)
            mock_connect.return_value = (backend_reader, backend_writer)
            
            with patch.object(handler, '_forward_data', new_callable=AsyncMock):
                await handler.handle_connection(reader, writer)
        
        assert not writer.closed
    
    async def test_header_size_limit(self):
        """Test that headers exceeding 107 bytes are handled correctly."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Create a header that would exceed 107 bytes if fully read
        # But only first 107 bytes should be read
        long_data = b'PROXY TCP4 ' + b'1' * 200 + b'\r\n'
        reader = MockStreamReader(long_data)
        writer = MockStreamWriter()
        
        with patch('asyncio.open_connection') as mock_connect:
            backend_reader = AsyncMock()
            backend_writer = AsyncMock()
            mock_connect.return_value = (backend_reader, backend_writer)
            
            await handler.handle_connection(reader, writer)
        
        # Should close connection due to invalid header
        assert writer.closed
    
    async def test_invalid_protocol(self):
        """Test invalid protocol name causes connection abort."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        data = b'PROXY INVALID 192.168.1.1 192.168.1.2 56324 443\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        await handler.handle_connection(reader, writer)
        
        # Should close connection immediately
        assert writer.closed
    
    async def test_invalid_ipv4_address(self):
        """Test invalid IPv4 address causes connection abort."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Invalid IPv4 (256 > 255)
        data = b'PROXY TCP4 192.168.1.256 192.168.1.2 56324 443\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        await handler.handle_connection(reader, writer)
        assert writer.closed
    
    async def test_invalid_ipv6_address(self):
        """Test invalid IPv6 address causes connection abort."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Invalid IPv6
        data = b'PROXY TCP6 invalid::ipv6 2001:db8::2 56324 443\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        await handler.handle_connection(reader, writer)
        assert writer.closed
    
    async def test_port_range_validation(self):
        """Test port range validation (0-65535)."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Port > 65535
        data = b'PROXY TCP4 192.168.1.1 192.168.1.2 70000 443\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        await handler.handle_connection(reader, writer)
        assert writer.closed
    
    async def test_port_leading_zeros(self):
        """Test that ports with leading zeros are rejected."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Port with leading zeros
        data = b'PROXY TCP4 192.168.1.1 192.168.1.2 00443 443\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        await handler.handle_connection(reader, writer)
        assert writer.closed
    
    async def test_wrong_field_count(self):
        """Test wrong number of fields causes abort."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Missing port field
        data = b'PROXY TCP4 192.168.1.1 192.168.1.2 56324\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        await handler.handle_connection(reader, writer)
        assert writer.closed
    
    async def test_non_proxy_data_forwarded(self):
        """Test non-PROXY data is forwarded as-is."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Regular HTTP request (no PROXY header)
        data = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        reader = MockStreamReader(data)
        writer = MockStreamWriter()
        
        with patch('asyncio.open_connection') as mock_connect:
            backend_reader = AsyncMock()
            backend_writer = MagicMock()
            backend_writer.get_extra_info.return_value = ('127.0.0.1', 12345)
            mock_connect.return_value = (backend_reader, backend_writer)
            
            with patch.object(handler, '_forward_data', new_callable=AsyncMock):
                await handler.handle_connection(reader, writer)
            
            # Verify data was forwarded
            backend_writer.write.assert_called_with(data)
        
        assert not writer.closed
    
    async def test_parse_proxy_v1_edge_cases(self):
        """Test _parse_proxy_v1 method edge cases."""
        handler = ProxyProtocolHandler('localhost', 9000)
        
        # Test valid cases
        ip, port = await handler._parse_proxy_v1(b'PROXY TCP4 1.2.3.4 5.6.7.8 12345 80')
        assert ip == '1.2.3.4'
        assert port == 12345
        
        # Test UNKNOWN returns zeros
        ip, port = await handler._parse_proxy_v1(b'PROXY UNKNOWN')
        assert ip == '0.0.0.0'
        assert port == 0
        
        # Test port "0" is valid (no leading zero)
        ip, port = await handler._parse_proxy_v1(b'PROXY TCP4 1.2.3.4 5.6.7.8 0 80')
        assert port == 0
        
        # Test non-ASCII raises
        with pytest.raises(ValueError, match="Non-ASCII"):
            await handler._parse_proxy_v1(b'PROXY TCP4 \xff\xfe 5.6.7.8 12345 80')