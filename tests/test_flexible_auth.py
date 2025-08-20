"""Tests for the flexible authentication system.

This module tests the FlexibleAuthService and related components
for proper authentication and authorization across different layers.
"""

import pytest
import json
import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import Request, HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from src.auth import (
    FlexibleAuthService,
    AuthResult,
    EndpointAuthConfig,
    RouteAuthConfig,
    ProxyAuthConfig,
    TokenValidation,
    OAuthValidation
)
from src.auth.dependencies import AuthDep
from src.auth.defaults import DEFAULT_ENDPOINT_CONFIGS, load_default_configs


@pytest.fixture
def mock_storage():
    """Create a mock storage instance."""
    storage = AsyncMock()
    storage.redis_client = AsyncMock()
    storage.get_api_token = AsyncMock()
    storage.get_proxy_target = AsyncMock()
    storage.get_route = AsyncMock()
    storage.get_certificate = AsyncMock()
    storage.list_auth_configs = AsyncMock(return_value=[])
    return storage


@pytest.fixture
def auth_service_sync(mock_storage):
    """Create a FlexibleAuthService instance (not initialized)."""
    service = FlexibleAuthService(storage=mock_storage)
    # Mark as loaded to avoid actual loading
    service._configs_loaded = True
    return service


@pytest.fixture
def mock_request():
    """Create a mock FastAPI request."""
    request = MagicMock(spec=Request)
    request.url.path = "/api/v1/tokens"
    request.method = "GET"
    request.headers = {}
    request.cookies = {}
    request.path_params = {}
    request.app.state.auth_service = None
    request.app.state.async_storage = None
    request.app.state.storage = None
    return request


class TestFlexibleAuthService:
    """Test FlexibleAuthService class."""
    
    def test_initialize(self, auth_service_sync):
        """Test auth service initialization."""
        assert auth_service_sync._configs_loaded is True
        assert auth_service_sync._oauth_protector is None  # No OAuth components provided
    
    @pytest.mark.asyncio
    async def test_check_endpoint_auth_no_config(self, auth_service_sync, mock_request):
        """Test endpoint auth check with no configuration."""
        result = await auth_service_sync.check_endpoint_auth(
            request=mock_request,
            path="/unknown/path",
            method="GET"
        )
        
        # Should default to public for non-API paths
        assert result.authenticated is True
        assert result.auth_type == "none"
        assert result.principal == "anonymous"
    
    @pytest.mark.asyncio
    async def test_check_endpoint_auth_api_default(self, auth_service_sync, mock_request):
        """Test endpoint auth check for API path with no config."""
        result = await auth_service_sync.check_endpoint_auth(
            request=mock_request,
            path="/api/v1/data",
            method="GET"
        )
        
        # Should default to bearer for API paths
        assert result.authenticated is False
        assert result.error == "no_credentials"
    
    @pytest.mark.asyncio
    async def test_validate_bearer_token_valid(self, auth_service_sync, mock_storage):
        """Test valid bearer token validation."""
        token = "acm_test_token_12345"
        token_hash = f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"
        
        mock_storage.get_api_token.return_value = {
            "name": "test_token",
            "cert_email": "test@example.com",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        result = await auth_service_sync.validate_bearer_token(token)
        
        assert result.valid is True
        assert result.token_hash == token_hash
        assert result.token_name == "test_token"
        assert result.is_admin is False
    
    @pytest.mark.asyncio
    async def test_validate_bearer_token_admin(self, auth_service):
        """Test admin token validation."""
        with patch.dict('os.environ', {'ADMIN_TOKEN': 'acm_admin_token'}):
            result = await auth_service_sync.validate_bearer_token('acm_admin_token')
            
            assert result.valid is True
            assert result.token_name == "ADMIN"
            assert result.is_admin is True
            assert result.owns_resource is True  # Admin owns everything
    
    @pytest.mark.asyncio
    async def test_validate_bearer_token_invalid_format(self, auth_service):
        """Test bearer token with invalid format."""
        result = await auth_service_sync.validate_bearer_token('invalid_token')
        
        assert result.valid is False
        assert result.error == "invalid_format"
    
    @pytest.mark.asyncio
    async def test_check_route_auth(self, auth_service_sync, mock_request, mock_storage):
        """Test route authentication check."""
        route_auth_config = {
            "auth_type": "bearer",
            "cache_ttl": 60
        }
        
        mock_storage.redis_client.get.return_value = json.dumps(route_auth_config)
        
        result = await auth_service_sync.check_route_auth(
            request=mock_request,
            route_id="test_route"
        )
        
        # Should fail without credentials
        assert result.authenticated is False
        assert result.error == "no_credentials"
    
    @pytest.mark.asyncio
    async def test_check_proxy_auth(self, auth_service_sync, mock_request, mock_storage):
        """Test proxy authentication check."""
        from src.proxy.models import ProxyTarget
        
        proxy_target = ProxyTarget(
            hostname="api.example.com",
            target_url="http://backend:3000",
            auth_enabled=True,
            auth_mode="enforce"
        )
        
        mock_storage.get_proxy_target.return_value = proxy_target
        
        result = await auth_service_sync.check_proxy_auth(
            request=mock_request,
            hostname="api.example.com",
            path="/api/data"
        )
        
        # Should fail without credentials
        assert result.authenticated is False
        assert result.error == "no_credentials"
    
    @pytest.mark.asyncio
    async def test_check_proxy_auth_excluded_path(self, auth_service_sync, mock_request, mock_storage):
        """Test proxy auth with excluded path."""
        from src.proxy.models import ProxyTarget
        
        proxy_target = ProxyTarget(
            hostname="api.example.com",
            target_url="http://backend:3000",
            auth_enabled=True,
            auth_excluded_paths=["/.well-known/", "/health"]
        )
        
        mock_storage.get_proxy_target.return_value = proxy_target
        
        result = await auth_service_sync.check_proxy_auth(
            request=mock_request,
            hostname="api.example.com",
            path="/.well-known/openid-configuration"
        )
        
        # Should pass for excluded path
        assert result.authenticated is True
        assert result.auth_type == "none"
        assert result.metadata.get("excluded_path") is True
    
    @pytest.mark.asyncio
    async def test_apply_auth_config_none(self, auth_service_sync, mock_request):
        """Test applying 'none' auth type."""
        from src.auth.models import AuthConfig
        
        config = AuthConfig(auth_type="none")
        
        result = await auth_service_sync._apply_auth_config(
            config=config,
            request=mock_request,
            credentials=None
        )
        
        assert result.authenticated is True
        assert result.auth_type == "none"
        assert result.principal == "anonymous"
    
    @pytest.mark.asyncio
    async def test_apply_auth_config_bearer_with_token(self, auth_service_sync, mock_request, mock_storage):
        """Test applying bearer auth with valid token."""
        from src.auth.models import AuthConfig
        
        config = AuthConfig(auth_type="bearer")
        
        token = "acm_test_token"
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        
        mock_storage.get_api_token.return_value = {
            "name": "test",
            "cert_email": "test@example.com"
        }
        
        result = await auth_service_sync._apply_auth_config(
            config=config,
            request=mock_request,
            credentials=credentials
        )
        
        assert result.authenticated is True
        assert result.auth_type == "bearer"
        assert result.principal == "test"
    
    @pytest.mark.asyncio
    async def test_cache_functionality(self, auth_service_sync, mock_request):
        """Test auth result caching."""
        # First call - not cached
        result1 = await auth_service_sync.check_endpoint_auth(
            request=mock_request,
            path="/test/path",
            method="GET"
        )
        assert result1.cached is False
        
        # Second call - should be cached
        result2 = await auth_service_sync.check_endpoint_auth(
            request=mock_request,
            path="/test/path",
            method="GET"
        )
        assert result2.cached is True
        assert result2.cache_key is not None
        
        # Clear cache
        auth_service_sync.clear_cache()
        
        # Third call - not cached after clear
        result3 = await auth_service_sync.check_endpoint_auth(
            request=mock_request,
            path="/test/path",
            method="GET"
        )
        assert result3.cached is False


class TestAuthDep:
    """Test AuthDep dependency class."""
    
    @pytest.mark.asyncio
    async def test_auth_dep_bearer(self, mock_request, mock_storage):
        """Test AuthDep with bearer auth type."""
        dep = AuthDep(auth_type="bearer")
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="acm_test_token"
        )
        
        mock_storage.get_api_token.return_value = {
            "name": "test",
            "cert_email": "test@example.com"
        }
        
        # Mock app state
        mock_request.app.state.async_storage = mock_storage
        
        with patch('src.auth.service.FlexibleAuthService.initialize', new_callable=AsyncMock):
            result = await dep(mock_request, credentials)
        
        assert result.authenticated is True
        assert result.auth_type == "bearer"
    
    @pytest.mark.asyncio
    async def test_auth_dep_admin(self, mock_request):
        """Test AuthDep with admin requirement."""
        dep = AuthDep(admin=True)
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="not_admin_token"
        )
        
        # Mock app state
        mock_request.app.state.async_storage = AsyncMock()
        
        with pytest.raises(HTTPException) as exc_info:
            await dep(mock_request, credentials)
        
        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_auth_dep_no_credentials(self, mock_request):
        """Test AuthDep with no credentials."""
        dep = AuthDep(auth_type="bearer")
        
        # Mock app state
        mock_request.app.state.async_storage = AsyncMock()
        
        with pytest.raises(HTTPException) as exc_info:
            await dep(mock_request, None)
        
        assert exc_info.value.status_code == 401


class TestDefaultConfigs:
    """Test default configuration loading."""
    
    @pytest.mark.asyncio
    async def test_load_default_configs(self, mock_storage):
        """Test loading default configurations."""
        mock_storage.redis_client.get.return_value = None  # No existing configs
        mock_storage.redis_client.set.return_value = True
        
        loaded = await load_default_configs(mock_storage)
        
        assert loaded > 0
        assert mock_storage.redis_client.set.called
    
    def test_default_configs_structure(self):
        """Test default configurations have correct structure."""
        for config in DEFAULT_ENDPOINT_CONFIGS:
            assert "path_pattern" in config
            assert "auth_type" in config
            assert config["auth_type"] in ["none", "bearer", "admin", "oauth"]
            assert "priority" in config
            assert "description" in config


class TestEndpointPatternMatching:
    """Test endpoint pattern matching logic."""
    
    def test_path_matches_exact(self, auth_service_sync):
        """Test exact path matching."""
        assert auth_service_sync._path_matches_pattern("/api/v1/tokens", "/api/v1/tokens") is True
        assert auth_service_sync._path_matches_pattern("/api/v1/tokens", "/api/v1/certs") is False
    
    def test_path_matches_wildcard(self, auth_service_sync):
        """Test wildcard pattern matching."""
        assert auth_service_sync._path_matches_pattern("/api/v1/tokens/test", "/api/v1/tokens/*") is True
        assert auth_service_sync._path_matches_pattern("/api/v1/tokens", "/api/v1/tokens/*") is False
        assert auth_service_sync._path_matches_pattern("/anything", "*") is True
    
    def test_path_matches_partial_wildcard(self, auth_service_sync):
        """Test partial wildcard patterns."""
        assert auth_service_sync._path_matches_pattern("/api/v1/tokens", "/api/*/tokens") is True
        assert auth_service_sync._path_matches_pattern("/api/v2/tokens", "/api/*/tokens") is True
        assert auth_service_sync._path_matches_pattern("/api/v1/certs", "/api/*/tokens") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])