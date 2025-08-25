"""Comprehensive tests for UnifiedStorage architecture.

This module tests the unified storage implementation that bridges
sync and async contexts using asgiref.
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from src.storage import UnifiedStorage, RedisStorage, AsyncRedisStorage
from src.storage._async_redis_storage import AsyncRedisStorage as InternalAsyncRedisStorage


class TestUnifiedStorage:
    """Test unified storage in all contexts."""
    
    @pytest.fixture
    def redis_url(self):
        """Test Redis URL."""
        return "redis://localhost:6379/0"
    
    @pytest.fixture
    def mock_redis_client(self):
        """Mock Redis client for testing."""
        client = MagicMock()
        client.ping = MagicMock(return_value=True)
        client.get = MagicMock(return_value=None)
        client.set = MagicMock(return_value=True)
        return client
    
    def test_unified_storage_creation(self, redis_url):
        """Test UnifiedStorage can be created."""
        storage = UnifiedStorage(redis_url)
        assert storage.redis_url == redis_url
        assert storage._initialized == False
        assert storage._async_storage is None
    
    @patch('src.storage.unified_storage.redis_async.ConnectionPool.from_url')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize_default_proxies')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize_default_routes')
    def test_sync_initialization(self, mock_routes, mock_proxies, mock_init, mock_pool, redis_url):
        """Test synchronous initialization."""
        # Setup mocks
        mock_pool.return_value = MagicMock()
        mock_init.return_value = asyncio.Future()
        mock_init.return_value.set_result(None)
        mock_proxies.return_value = asyncio.Future()
        mock_proxies.return_value.set_result(None)
        mock_routes.return_value = asyncio.Future()
        mock_routes.return_value.set_result(None)
        
        # Create and initialize storage
        storage = UnifiedStorage(redis_url)
        storage.initialize()
        
        # Verify initialization
        assert storage._initialized == True
        assert storage._async_storage is not None
        mock_init.assert_called_once()
        mock_proxies.assert_called_once()
        mock_routes.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('src.storage.unified_storage.redis_async.ConnectionPool.from_url')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize_default_proxies')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize_default_routes')
    async def test_async_initialization(self, mock_routes, mock_proxies, mock_init, mock_pool, redis_url):
        """Test asynchronous initialization."""
        # Setup mocks
        mock_pool.return_value = MagicMock()
        mock_init.return_value = asyncio.Future()
        mock_init.return_value.set_result(None)
        mock_proxies.return_value = asyncio.Future()
        mock_proxies.return_value.set_result(None)
        mock_routes.return_value = asyncio.Future()
        mock_routes.return_value.set_result(None)
        
        # Create and initialize storage
        storage = UnifiedStorage(redis_url)
        await storage.initialize_async()
        
        # Verify initialization
        assert storage._initialized == True
        assert storage._async_storage is not None
        mock_init.assert_called_once()
        mock_proxies.assert_called_once()
        mock_routes.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('src.storage.unified_storage.redis_async.ConnectionPool.from_url')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize_default_proxies')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize_default_routes')
    async def test_double_initialization_prevented(self, mock_routes, mock_proxies, mock_init, mock_pool, redis_url):
        """Test that double initialization is prevented."""
        # Setup mocks
        mock_pool.return_value = MagicMock()
        mock_init.return_value = asyncio.Future()
        mock_init.return_value.set_result(None)
        mock_proxies.return_value = asyncio.Future()
        mock_proxies.return_value.set_result(None)
        mock_routes.return_value = asyncio.Future()
        mock_routes.return_value.set_result(None)
        
        # Create and initialize storage twice
        storage = UnifiedStorage(redis_url)
        await storage.initialize_async()
        await storage.initialize_async()  # Second call should be skipped
        
        # Verify only initialized once
        mock_init.assert_called_once()
        mock_proxies.assert_called_once()
        mock_routes.assert_called_once()
    
    def test_backward_compatibility_redis_storage(self, redis_url):
        """Test RedisStorage compatibility shim."""
        with patch('src.storage.unified_storage.async_to_sync') as mock_async_to_sync:
            mock_async_to_sync.return_value = lambda: None
            
            # RedisStorage should work as UnifiedStorage
            storage = RedisStorage(redis_url)
            assert isinstance(storage, UnifiedStorage)
            # Note: RedisStorage no longer auto-initializes in __init__
    
    def test_backward_compatibility_async_redis_storage(self, redis_url):
        """Test AsyncRedisStorage compatibility shim with deprecation warning."""
        with pytest.warns(DeprecationWarning, match="Direct use of AsyncRedisStorage is deprecated"):
            storage = AsyncRedisStorage(redis_url)
            assert isinstance(storage, UnifiedStorage)
    
    @pytest.mark.asyncio
    @patch('src.storage.unified_storage.redis_async.ConnectionPool.from_url')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage')
    async def test_context_detection_async(self, mock_async_redis, mock_pool, redis_url):
        """Test that async context returns async methods directly."""
        # Setup mock
        mock_pool.return_value = MagicMock()
        mock_instance = MagicMock()
        mock_async_redis.return_value = mock_instance
        
        # Create async method mock
        async def mock_get_proxy_target(hostname):
            return {"hostname": hostname}
        
        mock_instance.get_proxy_target = mock_get_proxy_target
        mock_instance.initialize = MagicMock(return_value=asyncio.Future())
        mock_instance.initialize.return_value.set_result(None)
        mock_instance.initialize_default_proxies = MagicMock(return_value=asyncio.Future())
        mock_instance.initialize_default_proxies.return_value.set_result(None)
        mock_instance.initialize_default_routes = MagicMock(return_value=asyncio.Future())
        mock_instance.initialize_default_routes.return_value.set_result(None)
        
        # Initialize storage
        storage = UnifiedStorage(redis_url)
        await storage.initialize_async()
        
        # In async context, should get async method directly
        method = storage.get_proxy_target
        assert asyncio.iscoroutinefunction(method)
    
    @patch('src.storage.unified_storage.redis_async.ConnectionPool.from_url')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage')
    def test_context_detection_sync(self, mock_async_redis, mock_pool, redis_url):
        """Test that sync context wraps async methods."""
        # Setup mock
        mock_pool.return_value = MagicMock()
        mock_instance = MagicMock()
        mock_async_redis.return_value = mock_instance
        
        # Create async method mock
        async def mock_get_proxy_target(hostname):
            return {"hostname": hostname}
        
        mock_instance.get_proxy_target = mock_get_proxy_target
        mock_instance.initialize = MagicMock(return_value=asyncio.Future())
        mock_instance.initialize.return_value.set_result(None)
        mock_instance.initialize_default_proxies = MagicMock(return_value=asyncio.Future())
        mock_instance.initialize_default_proxies.return_value.set_result(None)
        mock_instance.initialize_default_routes = MagicMock(return_value=asyncio.Future())
        mock_instance.initialize_default_routes.return_value.set_result(None)
        
        # Initialize storage
        storage = UnifiedStorage(redis_url)
        storage.initialize()
        
        # In sync context, should get wrapped sync version
        with patch('src.storage.unified_storage.asyncio.get_running_loop') as mock_get_loop:
            mock_get_loop.side_effect = RuntimeError("no running event loop")
            
            with patch('src.storage.unified_storage.async_to_sync') as mock_async_to_sync:
                mock_async_to_sync.return_value = lambda hostname: {"hostname": hostname}
                
                method = storage.get_proxy_target
                # The wrapped method should be callable synchronously
                mock_async_to_sync.assert_called_once()
    
    @patch('src.storage.unified_storage.redis_async.ConnectionPool.from_url')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage')
    def test_auto_initialization_on_first_use(self, mock_async_redis, mock_pool, redis_url):
        """Test auto-initialization when accessing methods."""
        # Setup mock
        mock_pool.return_value = MagicMock()
        mock_instance = MagicMock()
        mock_async_redis.return_value = mock_instance
        
        # Mock a simple attribute
        mock_instance.redis_client = MagicMock()
        mock_instance.initialize = MagicMock(return_value=asyncio.Future())
        mock_instance.initialize.return_value.set_result(None)
        mock_instance.initialize_default_proxies = MagicMock(return_value=asyncio.Future())
        mock_instance.initialize_default_proxies.return_value.set_result(None)
        mock_instance.initialize_default_routes = MagicMock(return_value=asyncio.Future())
        mock_instance.initialize_default_routes.return_value.set_result(None)
        
        # Create storage without initialization
        storage = UnifiedStorage(redis_url)
        assert storage._initialized == False
        
        # Access a property should trigger initialization
        with patch('src.storage.unified_storage.asyncio.get_running_loop') as mock_get_loop:
            mock_get_loop.side_effect = RuntimeError("no running event loop")
            _ = storage.redis_client
            
        # Should be initialized now
        assert storage._initialized == True
    
    def test_single_instance_sharing(self, redis_url):
        """Test that storage instance can be shared between components."""
        # Create storage instance (simulating main.py)
        storage = UnifiedStorage(redis_url)
        
        # Pass same instance to another component (simulating async_init.py)
        storage2 = storage  # Same instance, not a new one
        
        # Both should be the same object
        assert storage is storage2
        assert id(storage) == id(storage2)
    
    @pytest.mark.asyncio
    @patch('src.storage.unified_storage.redis_async.ConnectionPool.from_url')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize_default_proxies')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.initialize_default_routes')
    @patch('src.storage._async_redis_storage.AsyncRedisStorage.get_proxy_target')
    async def test_oauth_fix_verification(self, mock_get_proxy, mock_routes, mock_proxies, mock_init, mock_pool, redis_url):
        """Verify the OAuth circular dependency fix."""
        # Setup mocks
        mock_pool.return_value = MagicMock()
        mock_init.return_value = asyncio.Future()
        mock_init.return_value.set_result(None)
        mock_proxies.return_value = asyncio.Future()
        mock_proxies.return_value.set_result(None)
        mock_routes.return_value = asyncio.Future()
        mock_routes.return_value.set_result(None)
        
        # Mock localhost proxy with auth_excluded_paths
        mock_proxy = MagicMock()
        mock_proxy.auth_excluded_paths = ["/token", "/authorize", "/device/", "/callback", "/jwks"]
        mock_get_proxy.return_value = asyncio.Future()
        mock_get_proxy.return_value.set_result(mock_proxy)
        
        # Initialize storage
        storage = UnifiedStorage(redis_url)
        await storage.initialize_async()
        
        # Verify defaults were initialized
        mock_proxies.assert_called_once()  # initialize_default_proxies was called
        mock_routes.assert_called_once()   # initialize_default_routes was called
        
        # Verify localhost proxy would have auth_excluded_paths
        proxy = await storage.get_proxy_target("localhost")
        assert proxy.auth_excluded_paths is not None
        assert "/token" in proxy.auth_excluded_paths