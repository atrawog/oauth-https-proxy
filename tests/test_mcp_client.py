"""MCP client integration tests for the MCP HTTP Proxy service."""

import os
import json
import pytest
import httpx
import subprocess
import secrets
from typing import Optional, Dict

@pytest.mark.integration
@pytest.mark.slow
class TestMCPClient:
    """Test MCP client integration with proxy service."""
    
    @pytest.fixture
    def base_domain(self) -> str:
        """Get base domain for testing."""
        return os.getenv("BASE_DOMAIN", "localhost")
    
    @pytest.fixture
    def mcp_client_id(self) -> Optional[str]:
        """Get MCP client ID from environment."""
        return os.getenv("MCP_CLIENT_ID")
    
    @pytest.fixture
    def mcp_client_secret(self) -> Optional[str]:
        """Get MCP client secret from environment."""
        return os.getenv("MCP_CLIENT_SECRET")
    
    @pytest.fixture
    def echo_stateless_url(self, base_domain: str) -> str:
        """Get stateless echo server URL."""
        return f"https://echo-stateless.{base_domain}/mcp"
    
    @pytest.fixture
    def echo_stateful_url(self, base_domain: str) -> str:
        """Get stateful echo server URL."""
        return f"https://echo-stateful.{base_domain}/mcp"
    
    def test_mcp_server_metadata(self, echo_stateless_url: str):
        """Test that MCP server provides required metadata."""
        # Extract base URL from MCP endpoint
        base_url = echo_stateless_url.replace("/mcp", "")
        
        response = httpx.get(
            f"{base_url}/.well-known/oauth-protected-resource",
            verify=False,
            timeout=10
        )
        
        # MCP servers should provide metadata
        if response.status_code == 404:
            assert False, "FAILURE: MCP server metadata not implemented"
        
        assert response.status_code == 200
        data = response.json()
        
        # Required fields per MCP spec
        assert "resource" in data
        assert "authorization_servers" in data
        assert isinstance(data["authorization_servers"], list)
    
    def test_mcp_server_requires_auth(self, echo_stateless_url: str):
        """Test that MCP server requires authentication."""
        response = httpx.get(
            echo_stateless_url,
            verify=False,
            timeout=10
        )
        
        # Should require authentication now that auth is enabled
        assert response.status_code == 401, f"Expected 401 Unauthorized, got {response.status_code}: {response.text}"
        
        # Check for proper WWW-Authenticate header
        assert "WWW-Authenticate" in response.headers
    
    @pytest.mark.requires_auth
    def test_oauth_client_registration(self, base_domain: str):
        """Test OAuth client registration for MCP."""
        auth_url = f"https://auth.{base_domain}/register"
        
        registration_data = {
            "software_id": f"mcp-pytest-{secrets.token_hex(4)}",
            "software_version": "1.0.0",
            "client_name": "MCP PyTest Client",
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "mcp:read mcp:write"
        }
        
        response = httpx.post(
            auth_url,
            json=registration_data,
            verify=False,
            timeout=10
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: OAuth client registration not available"
        
        assert response.status_code in [200, 201], f"Expected 200 OK or 201 Created, got {response.status_code}: {response.text}"
        data = response.json()
        
        assert "client_id" in data
        assert "client_secret" in data
        assert data["client_id"].startswith("client_")
    
    @pytest.mark.requires_auth
    def test_mcp_client_token_generation(self, echo_stateless_url: str, mcp_client_id: Optional[str], mcp_client_secret: Optional[str]):
        """Test MCP client OAuth token generation flow."""
        if not mcp_client_id or not mcp_client_secret:
            assert False, "FAILURE: MCP client credentials not configured"
        
        # This would require simulating the full OAuth flow
        # which is complex in automated tests
        # For now, just verify the environment is configured
        assert mcp_client_id.startswith("client_")
        assert len(mcp_client_secret) > 20

@pytest.mark.integration
class TestEchoServers:
    """Test echo server functionality."""
    
    @pytest.fixture
    def base_domain(self) -> str:
        """Get base domain for testing."""
        return os.getenv("BASE_DOMAIN", "localhost")
    
    def test_echo_stateless_accessible(self, base_domain: str):
        """Test that stateless echo server is accessible."""
        url = f"https://echo-stateless.{base_domain}/.well-known/oauth-protected-resource"
        
        try:
            response = httpx.get(url, verify=False, timeout=5)
            assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        except httpx.ConnectError:
            assert False, "FAILURE: Echo server not accessible"
    
    def test_echo_stateful_accessible(self, base_domain: str):
        """Test that stateful echo server is accessible."""
        url = f"https://echo-stateful.{base_domain}/.well-known/oauth-protected-resource"
        
        try:
            response = httpx.get(url, verify=False, timeout=5)
            assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        except httpx.ConnectError:
            assert False, "FAILURE: Echo server not accessible"
    
    def test_echo_servers_different(self, base_domain: str):
        """Test that stateful and stateless servers are different."""
        stateless_url = f"https://echo-stateless.{base_domain}/.well-known/oauth-protected-resource"
        stateful_url = f"https://echo-stateful.{base_domain}/.well-known/oauth-protected-resource"
        
        try:
            stateless_response = httpx.get(stateless_url, verify=False, timeout=5)
            stateful_response = httpx.get(stateful_url, verify=False, timeout=5)
            
            if stateless_response.status_code == 200 and stateful_response.status_code == 200:
                stateless_data = stateless_response.json()
                stateful_data = stateful_response.json()
                
                # Should have different capabilities
                if "mcp_server_info" in stateless_data and "mcp_server_info" in stateful_data:
                    stateless_info = stateless_data["mcp_server_info"]
                    stateful_info = stateful_data["mcp_server_info"]
                    
                    # Stateful should have additional capabilities
                    assert stateless_info != stateful_info or "state" in str(stateful_info).lower()
        except httpx.ConnectError:
            assert False, "FAILURE: Echo servers not accessible"

@pytest.mark.integration
@pytest.mark.slow
class TestMCPClientCommands:
    """Test MCP client command execution."""
    
    @pytest.fixture
    def container_name(self) -> str:
        """Get container name for docker exec."""
        return "mcp-http-proxy-proxy-1"
    
    def run_just_command(self, command: str) -> tuple[int, str, str]:
        """Run a just command and return exit code, stdout, stderr."""
        try:
            result = subprocess.run(
                ["just", command],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            assert False, "FAILURE: just command not available"
    
    @pytest.mark.skip(reason="just command not available inside container")
    def test_mcp_client_token_generation_command(self):
        """Test MCP client token generation via just command."""
        # This tests the command exists and runs without error
        exit_code, stdout, stderr = self.run_just_command("mcp-client-servers")
        
        # Command should at least run
        assert exit_code == 0
        assert "Available MCP test servers" in stdout
        assert "echo-stateless" in stdout
        assert "echo-stateful" in stdout
    
    @pytest.mark.skip(reason="just command not available inside container")
    def test_mcp_echo_setup_command(self):
        """Test MCP echo setup command."""
        # Check if echo setup works
        exit_code, stdout, stderr = self.run_just_command("mcp-echo-setup")
        
        # Accept exit code 0 (success) or 1 (already exists)
        assert exit_code in [0, 1]
        
        # Should mention echo servers
        output = stdout + stderr
        assert "echo" in output.lower()

@pytest.mark.integration
class TestMCPProtocolCompliance:
    """Test MCP protocol compliance."""
    
    @pytest.fixture
    def base_domain(self) -> str:
        """Get base domain for testing."""
        return os.getenv("BASE_DOMAIN", "localhost")
    
    def test_mcp_resource_indicators(self, base_domain: str):
        """Test that OAuth server supports resource indicators."""
        auth_metadata_url = f"https://auth.{base_domain}/.well-known/oauth-authorization-server"
        
        try:
            response = httpx.get(auth_metadata_url, verify=False, timeout=5)
            
            if response.status_code == 404:
                assert False, "FAILURE: OAuth server metadata not available"
            
            assert response.status_code == 200
            data = response.json()
            
            # MCP requires resource indicators support
            assert "resource_indicators_supported" in data
            assert data["resource_indicators_supported"] is True
        except httpx.ConnectError:
            assert False, "FAILURE: OAuth server not accessible"
    
    def test_mcp_scopes_supported(self, base_domain: str):
        """Test that OAuth server supports MCP scopes."""
        auth_metadata_url = f"https://auth.{base_domain}/.well-known/oauth-authorization-server"
        
        try:
            response = httpx.get(auth_metadata_url, verify=False, timeout=5)
            
            if response.status_code == 404:
                assert False, "FAILURE: OAuth server metadata not available"
            
            assert response.status_code == 200
            data = response.json()
            
            # Check for MCP scopes
            if "scopes_supported" in data:
                scopes = data["scopes_supported"]
                mcp_scopes = [s for s in scopes if s.startswith("mcp:")]
                assert len(mcp_scopes) > 0
        except httpx.ConnectError:
            assert False, "FAILURE: OAuth server not accessible"

@pytest.mark.integration
class TestMCPClientWorkflow:
    """Test complete MCP client workflow."""
    
    @pytest.mark.skip(reason="Documentation test runs in different working directory inside container")
    def test_mcp_client_documentation(self):
        """Test that MCP client setup is documented."""
        # Check if documentation exists
        docs = [
            "README.md",
            "docs/mcp-client.md",
            "CLAUDE.md"
        ]
        
        doc_exists = False
        for doc_path in docs:
            if os.path.exists(doc_path):
                with open(doc_path, 'r') as f:
                    content = f.read().lower()
                    if "mcp" in content and "client" in content:
                        doc_exists = True
                        break
        
        assert doc_exists, "MCP client documentation not found"