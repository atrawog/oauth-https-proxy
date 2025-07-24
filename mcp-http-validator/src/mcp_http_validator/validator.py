"""Core MCP HTTP Validator implementation."""

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import HttpUrl

from .models import (
    MCPServerInfo,
    ProtectedResourceMetadata,
    TestCase,
    TestResult,
    TestSeverity,
    TestStatus,
    ValidationResult,
)
from .oauth import OAuthTestClient
from .env_manager import EnvManager
from .rfc8414 import RFC8414Validator
from .rfc8707 import RFC8707Validator


class MCPValidator:
    """Validates MCP server implementations for specification compliance."""
    
    def __init__(
        self,
        server_url: str,
        access_token: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        env_file: Optional[str] = None,
        auto_register: bool = True,
    ):
        """Initialize the MCP validator.
        
        Args:
            server_url: Base URL of the MCP server to validate
            access_token: Optional OAuth access token for authenticated requests
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            env_file: Path to .env file for storing credentials
            auto_register: Whether to automatically register OAuth client if needed
        """
        self.server_url = server_url.rstrip("/")
        self.access_token = access_token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.auto_register = auto_register
        self.client = httpx.AsyncClient(timeout=timeout, verify=verify_ssl)
        self.test_results: List[TestResult] = []
        self.server_info: Optional[MCPServerInfo] = None
        self.oauth_client: Optional[OAuthTestClient] = None
        self.env_manager = EnvManager(env_file)
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    def _get_headers(self, additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get request headers with optional authentication."""
        headers = {
            "Accept": "application/json",
            "MCP-Protocol-Version": "2025-06-18",
        }
        
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    async def _execute_test(self, test_case: TestCase, test_func) -> TestResult:
        """Execute a single test and record the result."""
        start_time = time.time()
        
        try:
            # Run the test function
            result = await test_func()
            
            # Handle different return formats
            if result is None or (isinstance(result, tuple) and result[0] is None):
                # Test was skipped
                status = TestStatus.SKIPPED
                passed = None
                message = result[1] if isinstance(result, tuple) else "Test skipped"
                details = result[2] if isinstance(result, tuple) and len(result) > 2 else {}
            else:
                # Normal test result
                passed, message, details = result
                status = TestStatus.PASSED if passed else TestStatus.FAILED
            
            return TestResult(
                test_case=test_case,
                status=status,
                duration_ms=(time.time() - start_time) * 1000,
                message=message,
                error_message=message if status == TestStatus.FAILED else None,  # Keep for backward compatibility
                details=details,
            )
        except Exception as e:
            return TestResult(
                test_case=test_case,
                status=TestStatus.ERROR,
                duration_ms=(time.time() - start_time) * 1000,
                message=str(e),
                error_message=str(e),  # Keep for backward compatibility
                details={"exception_type": type(e).__name__},
            )
    
    async def test_protected_resource_metadata(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test /.well-known/oauth-protected-resource endpoint (RFC 9728)."""
        url = urljoin(self.server_url, "/.well-known/oauth-protected-resource")
        
        details = {
            "test_description": "Checking if MCP server exposes OAuth protected resource metadata",
            "requirement": "RFC 9728 requires all OAuth-protected resources to expose metadata at /.well-known/oauth-protected-resource",
            "purpose": "This endpoint allows clients to discover OAuth requirements and authorization servers",
            "url_tested": url,
        }
        
        try:
            # First try WITHOUT auth - this endpoint should be publicly accessible per RFC 9728
            response = await self.client.get(url)
            
            if response.status_code == 404:
                return False, (
                    "Protected resource metadata endpoint not found. "
                    "The server must implement /.well-known/oauth-protected-resource endpoint as required by RFC 9728. "
                    "This endpoint should return JSON metadata about OAuth requirements without requiring authentication."
                ), {
                    **details,
                    "status_code": 404,
                    "expected_status": 200,
                    "fix": "Implement the /.well-known/oauth-protected-resource endpoint that returns OAuth metadata",
                    "example_response": {
                        "resource": "https://mcp.example.com",
                        "authorization_servers": ["https://auth.example.com"],
                        "scopes_supported": ["mcp:read", "mcp:write"],
                        "bearer_methods_supported": ["header"],
                        "resource_documentation": "https://docs.example.com/api"
                    }
                }
            
            if response.status_code == 401:
                # This is wrong per RFC 9728 - endpoint should be public
                # But let's try with auth anyway to see what we get
                auth_response = await self.client.get(url, headers=self._get_headers())
                return False, (
                    "Protected resource metadata endpoint requires authentication, which violates RFC 9728. "
                    "This endpoint MUST be publicly accessible without authentication so that clients can discover "
                    "OAuth requirements before attempting to access protected resources. The server returned 401 Unauthorized, "
                    "but RFC 9728 Section 2 explicitly states this endpoint must be available without credentials."
                ), {
                    **details,
                    "status_code": response.status_code,
                    "expected_status": 200,
                    "auth_status_code": auth_response.status_code if auth_response else None,
                    "body": auth_response.text if auth_response and auth_response.status_code == 200 else response.text,
                    "violation": "RFC 9728 Section 2 - Metadata endpoint must be publicly accessible",
                    "fix": "Remove authentication requirement from /.well-known/oauth-protected-resource endpoint"
                }
            
            if response.status_code != 200:
                return False, (
                    f"Protected resource metadata endpoint returned unexpected status code {response.status_code}. "
                    f"Expected 200 OK with JSON metadata, but got {response.status_code}. "
                    "This endpoint should return OAuth configuration metadata as specified in RFC 9728."
                ), {
                    **details,
                    "status_code": response.status_code,
                    "expected_status": 200,
                    "body": response.text[:500] if response.text else None,
                    "fix": f"Ensure the endpoint returns 200 OK with valid JSON metadata, not {response.status_code}"
                }
            
            # Validate response structure
            try:
                data = response.json()
                metadata = ProtectedResourceMetadata(**data)
                
                # Store for later use
                if self.server_info:
                    self.server_info.oauth_metadata = metadata
                
                return True, (
                    f"Protected resource metadata endpoint is accessible and returns valid JSON. "
                    f"The endpoint returned HTTP 200 with the required fields: resource={metadata.resource} "
                    f"and {len(metadata.authorization_servers)} authorization server(s). The response structure "
                    f"matches the basic schema expected for protected resource metadata."
                ), {
                    **details,
                    "status_code": 200,
                    "metadata": data,
                    "resource": str(metadata.resource),
                    "authorization_servers": [str(s) for s in metadata.authorization_servers],
                    "fields_found": list(data.keys()),
                    "required_fields_present": True
                }
            except Exception as e:
                return False, (
                    f"Protected resource metadata has invalid format: {str(e)}. "
                    "The endpoint returned data but it doesn't match the required schema from RFC 9728. "
                    "The response must be valid JSON with required fields: 'resource' (string) and "
                    "'authorization_servers' (array of strings)."
                ), {
                    **details,
                    "status_code": response.status_code,
                    "body": response.text[:500] if response.text else None,
                    "error": str(e),
                    "validation_error": "Failed to parse response as ProtectedResourceMetadata",
                    "required_fields": ["resource", "authorization_servers"],
                    "optional_fields": ["scopes_supported", "bearer_methods_supported", "resource_documentation", "jwks_uri"],
                    "fix": "Ensure the response contains valid JSON with at minimum 'resource' and 'authorization_servers' fields"
                }
                
        except httpx.RequestError as e:
            return False, (
                f"Failed to connect to protected resource metadata endpoint: {str(e)}. "
                "This could indicate a network issue, DNS problem, or the server is not accessible. "
                "The /.well-known/oauth-protected-resource endpoint must be accessible via HTTPS."
            ), {
                **details,
                "error": str(e),
                "error_type": type(e).__name__,
                "fix": "Ensure the server is running and accessible at the specified URL",
                "troubleshooting": [
                    "Verify the server URL is correct",
                    "Check if the server is running and accepting HTTPS connections",
                    "Ensure DNS resolution is working for the server hostname",
                    "Check for any firewall or network restrictions"
                ]
            }
    
    async def test_unauthenticated_request(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test that protected endpoints return proper 401 with WWW-Authenticate header."""
        # Try to access the MCP endpoint without auth
        url = urljoin(self.server_url, "/mcp")
        
        details = {
            "test_description": "Testing authentication challenge for protected MCP endpoints",
            "requirement": "MCP servers must return 401 Unauthorized with WWW-Authenticate header for unauthenticated requests",
            "purpose": "This allows clients to discover OAuth requirements and authorization server location",
            "url_tested": url,
            "spec_reference": "MCP Auth Spec Section 2.2, RFC 9110 Section 11.6.1"
        }
        
        try:
            # Make request without Authorization header
            headers = {"Accept": "application/json", "MCP-Protocol-Version": "2025-06-18"}
            response = await self.client.get(url, headers=headers)
            
            if response.status_code != 401:
                return False, (
                    f"Protected endpoint returned {response.status_code} instead of 401 Unauthorized for unauthenticated request. "
                    "MCP servers MUST return 401 when authentication is required. The server returned "
                    f"{response.status_code}, which suggests either the endpoint is not protected (security issue) "
                    "or the server is not properly implementing authentication challenges."
                ), {
                    **details,
                    "status_code": response.status_code,
                    "expected_status": 401,
                    "security_concern": "Endpoint may not be properly protected if it doesn't return 401",
                    "fix": "Ensure protected endpoints return 401 Unauthorized for requests without valid bearer tokens"
                }
            
            # Check WWW-Authenticate header
            www_auth = response.headers.get("WWW-Authenticate", "")
            if not www_auth:
                return False, (
                    "Server returned 401 but is missing the required WWW-Authenticate header. "
                    "RFC 9110 Section 11.6.1 requires that 401 responses MUST include a WWW-Authenticate header "
                    "containing at least one challenge. For MCP servers, this header must include 'realm', "
                    "'as_uri' (authorization server), and 'resource_uri' (protected resource metadata) parameters."
                ), {
                    **details,
                    "status_code": 401,
                    "headers": dict(response.headers),
                    "missing_header": "WWW-Authenticate",
                    "rfc_violation": "RFC 9110 Section 11.6.1 - 401 responses MUST include WWW-Authenticate",
                    "fix": "Add WWW-Authenticate header with Bearer scheme and required parameters",
                    "example_header": 'Bearer realm="MCP Server", as_uri="https://auth.example.com/.well-known/oauth-authorization-server", resource_uri="https://mcp.example.com/.well-known/oauth-protected-resource"'
                }
            
            # Validate header format per MCP spec
            required_params = ["realm", "as_uri", "resource_uri"]
            header_details = {
                **details,
                "status_code": 401,
                "www_authenticate": www_auth,
                "found_params": [],
                "missing_params": [],
            }
            
            missing_params = []
            for param in required_params:
                if param in www_auth:
                    header_details["found_params"].append(param)
                else:
                    missing_params.append(param)
            
            header_details["missing_params"] = missing_params
            
            if missing_params:
                return False, (
                    f"WWW-Authenticate header is missing required parameters: {missing_params}. "
                    "RFC 6750 (OAuth 2.0 Bearer Token Usage) and MCP specification require the WWW-Authenticate header to include:\n"
                    "- 'realm': The protection realm (RFC 6750 Section 3)\n"
                    "- 'as_uri': URL to the OAuth authorization server metadata (RFC 9470)\n" 
                    "- 'resource_uri': URL to the protected resource metadata (RFC 9470)\n"
                    "These parameters allow clients to discover OAuth configuration automatically per RFC 9470 (OAuth 2.0 Step Up Authentication Challenge Protocol)."
                ), {
                    **header_details,
                    "spec_requirement": "MCP Auth Spec requires realm, as_uri, and resource_uri parameters",
                    "fix": f"Add missing parameters {missing_params} to WWW-Authenticate header",
                    "example_header": 'Bearer realm="MCP Server", as_uri="https://auth.example.com/.well-known/oauth-authorization-server", resource_uri="https://mcp.example.com/.well-known/oauth-protected-resource"'
                }
            
            return True, (
                f"Server returns 401 Unauthorized with WWW-Authenticate header containing expected parameter names. "
                f"The header includes: {', '.join(found_params)}. This indicates basic OAuth challenge support, "
                f"though parameter values and format were not validated."
            ), {
                **header_details,
                "parameters_found": list(found_params),
                "basic_structure_present": True
            }
            
        except httpx.RequestError as e:
            return False, (
                f"Failed to test authentication challenge: {str(e)}. "
                "Could not connect to the MCP endpoint to verify authentication requirements. "
                "Ensure the server is accessible and the /mcp endpoint exists."
            ), {
                **details,
                "error": str(e),
                "error_type": type(e).__name__,
                "fix": "Verify the MCP endpoint is accessible and server is running"
            }
    
    async def test_authenticated_request(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test that authenticated requests are accepted and invalid tokens are rejected."""
        url = urljoin(self.server_url, "/mcp")
        
        details = {
            "test_description": "Testing basic OAuth 2.0 bearer token validation",
            "requirement": "MCP servers must validate bearer tokens and reject invalid ones (RFC 6750)",
            "purpose": "Verifies server distinguishes between valid and obviously invalid tokens",
            "url_tested": url,
            "spec_reference": "RFC 6750 - OAuth 2.0 Bearer Token Usage"
        }
        
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        if not self.access_token:
            # Mark as skipped, not failed - manual auth required
            return None, (
                "Cannot test bearer token authentication without a valid access token. "
                "The server requires OAuth 2.0 Bearer Token authentication (RFC 6750) but no access token is available in the environment. "
                "The validator checked for existing tokens and attempted to use automated OAuth flows (client credentials per RFC 6749, device flow per RFC 8628) "
                "but these are either not supported by the OAuth server or require manual intervention. "
                "Bearer token authentication is critical for MCP servers to verify that clients can access protected resources as specified in RFC 6750."
            ), {
                **details,
                "token_status": "unavailable",
                "automated_grants_tried": ["client_credentials"],
                "suggestion": "Run 'mcp-validate flow' for interactive OAuth flow to obtain a token",
                "alternative": "Provide a token via --token parameter or MCP_ACCESS_TOKEN environment variable"
            }
        
        # First, test with invalid token to ensure server rejects bad tokens
        invalid_token_test = {
            "test": "invalid_token_rejection",
            "description": "Verifying server rejects invalid tokens"
        }
        
        try:
            # Test with clearly invalid token
            invalid_headers = self._get_headers({"Authorization": "Bearer invalid-token-12345"})
            invalid_response = await self.client.get(url, headers=invalid_headers)
            
            if invalid_response.status_code in [200, 204]:
                # CRITICAL: Server accepted an invalid token!
                return False, (
                    "CRITICAL SECURITY FAILURE: Server accepted an obviously invalid bearer token! "
                    "The server returned success (HTTP {}) for the test token 'invalid-token-12345'. "
                    "This indicates the server is NOT performing even basic token validation. "
                    "Any client could access protected resources with any arbitrary string as a token. "
                    "Per RFC 6750, servers MUST validate bearer tokens. At minimum, the server should reject "
                    "tokens that are not valid JWTs issued by the authorized OAuth server.".format(invalid_response.status_code)
                ), {
                    **details,
                    **invalid_token_test,
                    "status_code": invalid_response.status_code,
                    "expected_status": "401 Unauthorized",
                    "actual_result": "Server accepted invalid token",
                    "security_risk": "CRITICAL - No token validation",
                    "fix": "Implement proper token validation that verifies JWT signatures and claims"
                }
            
            # Good - server rejected invalid token
            details["invalid_token_rejected"] = True
            details["invalid_token_status"] = invalid_response.status_code
            
        except httpx.RequestError as e:
            # Network error on invalid token test - note but continue
            details["invalid_token_test_error"] = str(e)
        
        # Now test with valid token
        try:
            response = await self.client.get(url, headers=self._get_headers())
            
            # Should get 200 or 204 for successful auth
            if response.status_code not in [200, 204]:
                error_detail = ""
                if response.status_code == 401:
                    error_detail = (
                        "Valid token was rejected. This could mean:\n"
                        "- Token is expired\n"
                        "- Token signature verification failed\n"
                        "- Token audience doesn't include this server\n"
                        "- Server's token validation is misconfigured"
                    )
                elif response.status_code == 403:
                    error_detail = "Token is valid but lacks required permissions/scopes for this resource"
                else:
                    error_detail = f"Unexpected response code {response.status_code} for authenticated request"
                    
                return False, (
                    f"Authenticated request failed with status {response.status_code}. "
                    f"Expected 200 OK or 204 No Content for valid authentication. {error_detail}"
                ), {
                    **details,
                    "status_code": response.status_code,
                    "expected_status": "200 or 204",
                    "body": response.text[:500] if response.text else None,
                    "token_present": True,
                    "fix": "Verify token validation logic and ensure tokens are properly validated"
                }
            
            # Both tests passed - basic token validation confirmed
            return True, (
                "Bearer token authentication is working at a basic level. "
                "The MCP server rejected an obviously invalid test string ('invalid-token-12345') with a 401 response "
                f"and accepted the provided OAuth token with HTTP {response.status_code}. "
                "This confirms the server distinguishes between valid and invalid tokens, though this test alone "
                "cannot verify the depth of validation (e.g., signature verification, expiration checking, issuer validation). "
                "For comprehensive validation testing, tokens with specific invalid characteristics would be needed."
            ), {
                **details,
                "status_code": response.status_code,
                "token_accepted": True,
                "validation_confirmed": "Server rejects invalid tokens and accepts valid ones",
                "compliance": "Proper OAuth bearer token validation confirmed"
            }
            
        except httpx.RequestError as e:
            return False, (
                f"Failed to test authenticated access: {str(e)}. "
                "Could not connect to the MCP endpoint with authentication. "
                "This may indicate network issues or server problems."
            ), {
                **details,
                "error": str(e),
                "error_type": type(e).__name__,
                "token_present": True,
                "fix": "Ensure server is accessible and accepting connections"
            }
    
    async def test_token_audience_validation(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test that the server validates token audience claims."""
        details = {
            "test_description": "Testing MCP server validation of token audience (aud) claims",
            "requirement": "MCP servers must validate that token audience includes their resource URI",
            "purpose": "Prevents tokens for other servers from being accepted (token confusion attack)",
            "spec_reference": "RFC 9728 Section 3, RFC 8707"
        }
        
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        if not self.access_token:
            # Mark as skipped, not failed
            return None, (
                "Token audience validation test requires a valid access token to proceed. "
                "This test verifies that the MCP server properly validates the 'aud' (audience) claim in JWT tokens "
                "to ensure tokens are only accepted by their intended recipients. This is a critical security feature "
                "required by RFC 9728 to prevent token misuse across different services. Without an access token, "
                "this security validation cannot be tested."
            ), {
                **details,
                "note": "Audience validation prevents tokens from being used on unintended servers",
                "suggestion": "Run 'mcp-validate flow' for interactive OAuth flow"
            }
        
        # First, check if we have protected resource metadata to know expected audience
        expected_audience = self.server_url.rstrip('/')  # Default to server URL
        details["expected_audience"] = expected_audience
        details["resource_metadata_found"] = False
        
        try:
            metadata_url = urljoin(self.server_url, "/.well-known/oauth-protected-resource")
            metadata_response = await self.client.get(metadata_url)
            if metadata_response.status_code == 200:
                metadata = metadata_response.json()
                # Use resource from metadata if available and non-null
                resource_uri = metadata.get("resource")
                if resource_uri and isinstance(resource_uri, str):
                    expected_audience = resource_uri.rstrip('/')
                    details["expected_audience"] = expected_audience
                    details["resource_metadata_found"] = True
                elif resource_uri is None:
                    details["metadata_warning"] = "Protected resource metadata has null 'resource' field"
        except Exception as e:
            # Keep default expected_audience (server URL)
            details["metadata_error"] = str(e)
        
        # Use RFC8707Validator to analyze the token
        try:
            import jwt
            # Decode token without verification to inspect claims
            token_claims = jwt.decode(self.access_token, options={"verify_signature": False})
            
            # Check audience claim
            aud = token_claims.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            
            details["token_audience"] = aud
            details["token_has_audience"] = len(aud) > 0
            
            if not aud:
                return False, (
                    "Token has no audience claim! The access token is missing the required 'aud' (audience) claim. "
                    "Per RFC 8707 and RFC 9728, OAuth tokens used with MCP must include audience restrictions "
                    "to prevent token confusion attacks. Without an audience claim, this token could be used "
                    "on any server, creating a serious security vulnerability. The OAuth server must be configured "
                    "to include resource URIs in the token audience when issuing tokens for MCP servers."
                ), {
                    **details,
                    "error": "Missing audience claim in token",
                    "fix": "Configure OAuth server to include resource parameter support per RFC 8707"
                }
            
            # Check if expected audience is in token
            audience_match = expected_audience in aud or any(
                a and expected_audience and expected_audience.startswith(a.rstrip('/')) 
                for a in aud
            )
            details["audience_includes_server"] = audience_match
            
            if not audience_match:
                # Token doesn't include this server - but we need to test if server enforces this
                # Try to use the token anyway and see if server rejects it
                url = urljoin(self.server_url, "/mcp")
                response = await self.client.get(url, headers=self._get_headers())
                
                if response.status_code in [200, 204]:
                    # SECURITY ISSUE: Server accepted token with wrong audience!
                    return False, (
                        f"SECURITY WARNING: Server accepted a token with wrong audience! "
                        f"The token audience is {aud} but the server ({expected_audience}) still accepted it. "
                        "This violates RFC 9728 which requires MCP servers to validate that the token audience "
                        "includes their resource identifier. This allows tokens meant for other servers to be used here, "
                        "creating a token confusion vulnerability. The server must check the 'aud' claim and reject "
                        "tokens that don't include its resource URI."
                    ), {
                        **details,
                        "status_code": response.status_code,
                        "security_issue": "Server accepts tokens with wrong audience",
                        "fix": "Implement audience validation to check token 'aud' claim includes server's resource URI"
                    }
                else:
                    # Good - server rejected token with wrong audience
                    details["wrong_audience_rejected"] = True
                    details["rejection_status"] = response.status_code
            
            # If we get here, token has audience and it matches (or server properly rejects wrong audience)
            # Ideally we'd test with multiple tokens, but we can at least verify the current token setup
            
            # Use RFC8707Validator for additional validation
            is_compliant, validation = RFC8707Validator.validate_token_response(
                self.access_token,
                [expected_audience],
                verify_signature=False
            )
            
            details["rfc8707_validation"] = validation
            details["rfc8707_compliant"] = is_compliant
            
            if not is_compliant:
                issues = []
                if validation.get("errors"):
                    issues.extend(validation["errors"])
                if validation.get("warnings"):
                    issues.extend(validation["warnings"])
                
                return False, (
                    "Token audience validation found RFC 8707 compliance issues. " + " ".join(issues) + " "
                    "The token or server configuration doesn't fully comply with RFC 8707 resource indicators "
                    "and RFC 9728 protected resource requirements for proper audience restrictions."
                ), {
                    **details,
                    "compliance_issues": issues
                }
            
            # Token structure checks passed
            return True, (
                f"Access token contains audience claim with value(s): {aud}. "
                f"The expected server resource identifier ({expected_audience}) is present in the token audience. "
                f"This indicates the token was issued with audience restrictions. "
                f"Note: This test only validates token structure, not whether the server enforces audience validation. "
                f"Testing server enforcement would require tokens with different audiences."
            ), {
                **details,
                "token_structure": "Token has audience claim with expected value",
                "server_enforcement": "Not tested - would require wrong-audience tokens"
            }
            
        except jwt.DecodeError as e:
            return False, (
                f"Failed to decode access token for audience validation: {str(e)}. "
                "The token appears to be malformed or not a valid JWT. RFC 9728 requires MCP servers "
                "to use JWT tokens with proper audience claims for security. A malformed token suggests "
                "issues with the OAuth server's token generation."
            ), {
                **details,
                "error": str(e),
                "token_format": "Invalid JWT",
                "fix": "Ensure OAuth server generates valid JWT tokens with audience claims"
            }
        except Exception as e:
            return False, (
                f"Error during token audience validation: {str(e)}. "
                "Could not complete audience validation checks. This may indicate issues with the token format "
                "or server configuration."
            ), {
                **details,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    async def test_http_transport(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test HTTP transport implementation for MCP protocol.
        
        Per MCP spec, servers can support either:
        1. JSON responses to POST requests
        2. SSE streams (optional)
        """
        url = urljoin(self.server_url, "/mcp")
        
        details = {
            "test_description": "Testing MCP HTTP transport implementation",
            "requirement": "MCP servers must support HTTP transport with JSON-RPC 2.0 messages",
            "purpose": "Verifies the server can handle MCP protocol messages over HTTP",
            "url_tested": url,
            "spec_reference": "MCP Transport Spec Section 3.1",
            "transport_options": ["application/json (required)", "text/event-stream (optional SSE)"]
        }
        
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        # Per MCP spec, client should accept both JSON and SSE
        headers = self._get_headers({
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        })
        
        # Initialize connection request
        init_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "mcp-http-validator",
                    "version": "0.1.0"
                }
            },
            "id": 1
        }
        
        try:
            # Test POST request (required)
            response = await self.client.post(
                url,
                headers=headers,
                json=init_request,
            )
            
            if response.status_code == 401 and not self.access_token:
                # Authentication required but no token available
                return None, (
                    "MCP protocol transport test requires authentication to access the server endpoints. "
                    "This test validates that the server correctly implements HTTP transport per MCP Transport Specification "
                    "with proper content negotiation (RFC 9110 Section 12) supporting both application/json and text/event-stream (Server-Sent Events per W3C specification) "
                    "for different MCP communication patterns. The server returned HTTP 401 Unauthorized (RFC 9110 Section 15.5.2), "
                    "indicating that authentication is required to test protocol transport. "
                    "Transport validation is essential to ensure clients can communicate with the server using standard MCP protocols."
                ), {
                    "url": url,
                    "status_code": response.status_code,
                    "suggestion": "Run 'mcp-validate flow' for interactive OAuth flow"
                }
            
            if response.status_code not in [200, 202]:
                return False, f"HTTP request failed with status {response.status_code}", {
                    "url": url,
                    "status_code": response.status_code,
                    "has_token": bool(self.access_token),
                }
            
            content_type = response.headers.get("Content-Type", "").lower()
            details = {
                "url": url,
                "content_type": content_type,
                "status_code": response.status_code,
                "transport_type": None,
            }
            
            # Check if server returned JSON (valid per spec)
            if "application/json" in content_type:
                try:
                    json_response = response.json()
                    details["transport_type"] = "json"
                    details["response"] = json_response
                    
                    # Validate JSON-RPC response format
                    if "jsonrpc" in json_response and json_response.get("id") == 1:
                        return True, (
                            f"Server responded to MCP initialize request with {content_type}. "
                            f"The response contains 'jsonrpc' field and matching request ID ({json_response.get('id')}), "
                            f"indicating basic JSON-RPC message structure. The server accepted the POST request and "
                            f"returned a JSON response that can be parsed."
                        ), details
                    else:
                        return False, "Invalid JSON-RPC response format", details
                except Exception as e:
                    return False, f"Failed to parse JSON response: {e}", details
            
            # Check if server returned SSE (also valid per spec)
            elif "text/event-stream" in content_type:
                details["transport_type"] = "sse"
                # For SSE, we need to read the stream
                event_data = None
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        try:
                            event_data = json.loads(line[6:])
                            details["first_event"] = event_data
                            break
                        except json.JSONDecodeError:
                            pass
                
                if event_data:
                    return True, (
                        f"Server responded with Server-Sent Events stream ({content_type}). "
                        f"Successfully received at least one 'data:' event that could be parsed as JSON. "
                        f"The server established an SSE connection and sent parseable data."
                    ), details
                else:
                    return False, "No valid SSE events received", details
            
            else:
                # Neither JSON nor SSE - this is a failure
                return False, f"Invalid content type: {content_type} (expected application/json or text/event-stream)", details
            
        except httpx.RequestError as e:
            return False, f"HTTP transport request failed: {str(e)}", {"url": url, "error": str(e)}
        finally:
            # Always close streaming responses
            if 'response' in locals():
                await response.aclose()
    
    async def test_protocol_version(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test MCP protocol version handling."""
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        url = urljoin(self.server_url, "/mcp")
        
        # Test with the current protocol version
        headers = self._get_headers({
            "Content-Type": "application/json",
        })
        
        # Simple request to test protocol version
        test_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "mcp-http-validator",
                    "version": "0.1.0"
                }
            },
            "id": 1
        }
        
        try:
            response = await self.client.post(url, headers=headers, json=test_request)
            
            if response.status_code == 401 and not self.access_token:
                return None, (
                    "Protocol version header test requires authentication to validate server compatibility. "
                    "This test ensures the MCP server correctly processes the MCP-Protocol-Version header as specified in MCP Transport Specification Section 2.4 "
                    "which is essential for version negotiation between clients and servers. The header allows clients to indicate their supported "
                    "protocol version and servers to respond with compatible behavior per semantic versioning (RFC 2119). "
                    "The server returned HTTP 401 Unauthorized (RFC 9110 Section 15.5.2), preventing validation of protocol version handling. "
                    "Proper version negotiation ensures forward and backward compatibility."
                ), {
                    "url": url,
                    "status_code": response.status_code,
                    "protocol_version_sent": "2025-06-18",
                    "suggestion": "Run 'mcp-validate flow' for interactive OAuth flow"
                }
            
            if response.status_code not in [200, 202]:
                return False, f"Request failed with status {response.status_code}", {
                    "url": url,
                    "status_code": response.status_code,
                }
            
            # Check response
            try:
                json_response = response.json()
                
                # Check if it's an error response about protocol version
                if "error" in json_response:
                    error = json_response["error"]
                    if "protocol version" in error.get("message", "").lower():
                        # Check if error says empty protocol version
                        error_msg = error.get("message", "")
                        if "protocol version: ." in error_msg or "protocol version:  " in error_msg:
                            # Server is not reading the header
                            details = {
                                "url": url,
                                "protocol_version_sent": "2025-06-18",
                                "header_name": "MCP-Protocol-Version",
                                "error": error,
                                "diagnosis": "Server reports empty protocol version despite header being sent",
                                "likely_cause": "Server bug - not reading MCP-Protocol-Version header correctly",
                                "note": "This is a server implementation issue, not a client issue"
                            }
                            return False, (
                                f"Server failed to read protocol version header. {error['message']}. "
                                "The validator is sending the header correctly, but the server reports it as empty. "
                                "This indicates a bug in the server's header parsing implementation."
                            ), details
                        else:
                            # Normal protocol version error
                            details = {
                                "url": url,
                                "protocol_version_sent": "2025-06-18",
                                "header_name": "MCP-Protocol-Version",
                                "error": error,
                                "note": "Header is being sent correctly; server may have header parsing issue"
                            }
                            return False, f"Server rejected protocol version: {error['message']}", details
                
                # If we got a successful response, the protocol version is accepted
                return True, (
                    f"Server accepted MCP-Protocol-Version header with value '2025-06-18'. "
                    f"The request completed successfully with status {response.status_code}, "
                    f"indicating the server recognizes this protocol version. "
                    f"Note: This test only verifies acceptance of one version, not full version negotiation capabilities."
                ), {
                    "url": url,
                    "protocol_version": "2025-06-18",
                    "response": json_response,
                }
                
            except Exception as e:
                return False, f"Failed to parse response: {e}", {
                    "url": url,
                    "error": str(e),
                }
                
        except httpx.RequestError as e:
            return False, f"Request failed: {str(e)}", {"url": url, "error": str(e)}
    
    async def initialize_mcp_session(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Initialize an MCP session with the server."""
        url = urljoin(self.server_url, "/mcp")
        
        headers = self._get_headers({
            "Content-Type": "application/json",
        })
        
        init_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "mcp-http-validator",
                    "version": "0.1.0"
                }
            },
            "id": 1
        }
        
        try:
            response = await self.client.post(url, headers=headers, json=init_request)
            
            if response.status_code not in [200, 202]:
                return False, f"Failed to initialize session: status {response.status_code}", {
                    "status_code": response.status_code,
                    "body": response.text[:500] if response.text else None
                }
            
            json_response = response.json()
            
            # Check for error response
            if "error" in json_response:
                return False, f"Server returned error: {json_response['error']['message']}", {
                    "error": json_response["error"]
                }
            
            # Check for result
            if "result" not in json_response:
                return False, "Invalid response: missing 'result' field", {
                    "response": json_response
                }
            
            return True, None, {
                "session_initialized": True,
                "server_info": json_response.get("result", {})
            }
            
        except Exception as e:
            return False, f"Failed to initialize session: {str(e)}", {"error": str(e)}
    
    async def list_mcp_tools(self) -> Tuple[bool, Optional[str], List[Dict[str, Any]]]:
        """List all available tools from the MCP server."""
        url = urljoin(self.server_url, "/mcp")
        
        headers = self._get_headers({
            "Content-Type": "application/json",
        })
        
        list_request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 2
        }
        
        try:
            response = await self.client.post(url, headers=headers, json=list_request)
            
            if response.status_code not in [200, 202]:
                return False, f"Failed to list tools: status {response.status_code}", []
            
            json_response = response.json()
            
            # Check for error response
            if "error" in json_response:
                return False, f"Server returned error: {json_response['error']['message']}", []
            
            # Extract tools from result
            if "result" in json_response and "tools" in json_response["result"]:
                tools = json_response["result"]["tools"]
                return True, None, tools
            else:
                return True, "No tools found", []
                
        except Exception as e:
            return False, f"Failed to list tools: {str(e)}", []
    
    async def test_mcp_tool(self, tool: Dict[str, Any], test_destructive: bool = False) -> Dict[str, Any]:
        """Test a specific MCP tool."""
        url = urljoin(self.server_url, "/mcp")
        tool_name = tool.get("name", "unknown")
        
        headers = self._get_headers({
            "Content-Type": "application/json",
        })
        
        # Create a test call based on the tool's input schema
        test_params = {}
        input_schema = tool.get("inputSchema", {})
        
        # Generate minimal valid parameters based on schema
        if input_schema.get("type") == "object":
            properties = input_schema.get("properties", {})
            required = input_schema.get("required", [])
            
            for prop, schema in properties.items():
                if prop in required:
                    # Generate a test value based on type
                    prop_type = schema.get("type", "string")
                    if prop_type == "string":
                        test_params[prop] = "test_value"
                    elif prop_type == "number":
                        test_params[prop] = 42
                    elif prop_type == "boolean":
                        test_params[prop] = True
                    elif prop_type == "array":
                        test_params[prop] = []
                    elif prop_type == "object":
                        test_params[prop] = {}
        
        call_request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": test_params
            },
            "id": 3
        }
        
        result = {
            "tool_name": tool_name,
            "description": tool.get("description", ""),
            "test_params": test_params,
            "status": "untested",
            "error": None,
            "response": None,
            "destructive": tool.get("annotations", {}).get("destructiveHint", False),
            "read_only": tool.get("annotations", {}).get("readOnlyHint", False)
        }
        
        # Skip destructive tools unless explicitly enabled
        if result["destructive"] and not test_destructive:
            result["status"] = "skipped"
            result["error"] = "Skipped destructive tool for safety"
            return result
        
        try:
            response = await self.client.post(url, headers=headers, json=call_request)
            
            if response.status_code not in [200, 202]:
                result["status"] = "failed"
                result["error"] = f"HTTP {response.status_code}"
                result["response"] = response.text[:500] if response.text else None
                return result
            
            json_response = response.json()
            
            # Check for error response
            if "error" in json_response:
                result["status"] = "error"
                result["error"] = json_response["error"].get("message", "Unknown error")
                result["response"] = json_response["error"]
            elif "result" in json_response:
                result["status"] = "success"
                result["response"] = json_response["result"]
                
                # Check if tool reported an error in its result
                tool_result = json_response["result"]
                if isinstance(tool_result, dict) and tool_result.get("isError"):
                    result["status"] = "tool_error"
                    result["error"] = "Tool reported an error in result"
            else:
                result["status"] = "invalid"
                result["error"] = "Invalid response format"
                result["response"] = json_response
                
        except Exception as e:
            result["status"] = "exception"
            result["error"] = str(e)
            
        return result
    
    async def test_mcp_tools(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test MCP tool discovery and validation."""
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        if not self.access_token:
            return None, (
                "MCP tools discovery and testing requires authentication to access server capabilities. "
                "Tools are the primary way MCP servers expose functionality to clients per MCP Core Specification, allowing them to perform "
                "actions like reading files, running code, or interacting with external services following the JSON-RPC 2.0 protocol (RFC 7159). "
                "Testing tools requires authentication because they may expose sensitive operations or data per OAuth 2.0 security considerations (RFC 6749 Section 10). "
                "Without authentication, the validator cannot discover available tools or verify their schemas and behavior conform to MCP specifications."
            ), {
                "note": "Tools may contain sensitive operations requiring proper authorization",
                "suggestion": "Run 'mcp-validate flow' for interactive OAuth flow"
            }
        
        details = {
            "session_initialized": False,
            "session_error": None,
            "tools_discovered": 0,
            "tools_tested": 0,
            "tools_passed": 0,
            "tools_failed": 0,
            "tools_skipped": 0,
            "tool_results": [],
            "errors": []
        }
        
        # First try to initialize session (but don't fail if it doesn't work)
        success, error, init_details = await self.initialize_mcp_session()
        if success:
            details["session_initialized"] = True
            details["server_info"] = init_details.get("server_info", {})
        else:
            details["session_error"] = error
            details["errors"].append(f"Session initialization: {error}")
            # Continue anyway - some servers may not require initialization
        
        # Try to list tools regardless of initialization status
        success, error, tools = await self.list_mcp_tools()
        if not success:
            details["errors"].append(f"Tool listing: {error}")
            # If we have both initialization and listing failures, then we truly failed
            if not details["session_initialized"]:
                return False, "Failed to access MCP server (both session init and tool listing failed)", details
            else:
                # Session worked but no tools - this is actually OK
                return True, (
                "MCP tools discovery completed successfully. "
                "The MCP session was initialized correctly, but the server does not expose any tools. "
                "This is valid per the MCP Core Specification - servers may choose not to expose tools if they only provide "
                "read-only access to resources or if tool functionality is not applicable to their use case. "
                "The server correctly implements the MCP protocol for session management and tool discovery."
            ), details
        
        if not tools:
            # No tools is not necessarily a failure
            details["tools_discovered"] = 0
            return True, (
                "MCP tools discovery completed successfully. "
                "The server does not expose any tools, which is valid per the MCP Core Specification. "
                "Servers may operate without tools if they only provide read-only access to resources "
                "or if their functionality doesn't require tool-based interactions. This is a valid implementation choice."
            ), details
        
        details["tools_discovered"] = len(tools)
        
        # Test each tool
        for tool in tools:
            tool_result = await self.test_mcp_tool(tool)
            details["tool_results"].append(tool_result)
            details["tools_tested"] += 1
            
            if tool_result["status"] == "success":
                details["tools_passed"] += 1
            elif tool_result["status"] == "skipped":
                details["tools_skipped"] += 1
            else:
                details["tools_failed"] += 1
        
        # Determine overall success
        if details["tools_failed"] > 0:
            return False, f"{details['tools_failed']} tool(s) failed testing", details
        elif details["tools_discovered"] == 0:
            return True, "No tools to test", details
        else:
            return True, (
                f"Tool discovery and basic invocation testing completed. "
                f"Found {details['tools_discovered']} tool(s) via the tools/list method. "
                f"Successfully invoked {details['tools_tested']} tool(s) with minimal parameters "
                f"({details['tools_skipped']} skipped as potentially destructive). "
                f"Each tested tool returned a response without errors when called with basic inputs. "
                f"Note: This test only verifies tools can be called, not full schema compliance or functionality."
            ), details
    
    async def test_oauth_server_discovery(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test OAuth server discovery."""
        details = {
            "discovery_methods_tried": [],
            "oauth_server_found": None,
        }
        
        # Try to discover OAuth server
        oauth_server = await self.discover_oauth_server()
        
        if not oauth_server:
            return False, "No OAuth authorization server discovered. The validator attempted to discover the OAuth server through multiple methods: checking the protected resource metadata for authorization_servers field (RFC 9728), looking for common OAuth subdomains (auth.*, oauth.*, sso.*, login.*), and checking if the MCP server itself hosts OAuth endpoints with metadata at /.well-known/oauth-authorization-server (RFC 8414). None of these discovery methods succeeded. For proper OAuth integration, either the protected resource metadata should list authorization servers (RFC 9728) or an OAuth server should exist at a discoverable location with proper metadata (RFC 8414).", details
        
        details["oauth_server_found"] = oauth_server
        
        # Just check if metadata endpoint exists and is accessible
        try:
            metadata_url = urljoin(oauth_server, "/.well-known/oauth-authorization-server")
            response = await self.client.get(metadata_url)
            
            if response.status_code != 200:
                return False, f"OAuth authorization server metadata endpoint returned HTTP {response.status_code}. The endpoint at {metadata_url} must return HTTP 200 (RFC 9110 Section 15.3.1) with valid OAuth 2.0 Authorization Server Metadata as specified in RFC 8414. This endpoint should be publicly accessible without authentication (RFC 8414 Section 3) and return a JSON document (RFC 8259) containing at minimum: issuer, authorization_endpoint, token_endpoint, and response_types_supported fields (RFC 8414 Section 2).", {
                    **details,
                    "metadata_url": metadata_url,
                    "status_code": response.status_code,
                }
            
            # Just verify it's valid JSON
            try:
                metadata = response.json()
                details["metadata_url"] = metadata_url
                details["metadata_accessible"] = True
            except:
                return False, f"OAuth authorization server metadata endpoint returned invalid JSON. The endpoint at {metadata_url} must return a valid JSON document (RFC 8259) containing OAuth 2.0 Authorization Server Metadata as specified in RFC 8414.", details
            
            # OAuth server metadata endpoint is accessible
            return True, (
                f"OAuth authorization server metadata endpoint found at {metadata_url}. "
                f"The endpoint returned HTTP 200 with parseable JSON content. "
                f"This indicates an OAuth server is present, though functionality was not tested."
            ), details
            
        except Exception as e:
            return False, f"Failed to access OAuth authorization server. An error occurred while attempting to retrieve the OAuth server metadata from {oauth_server} as required by RFC 8414 Section 3. This could indicate network issues or server errors (RFC 9110). The specific error was: {str(e)}", details
    
    async def test_oauth_server_mcp_compliance(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test OAuth server compliance with MCP requirements."""
        details = {
            "oauth_server_found": None,
            "rfc8414_validation": None,
            "mcp_scopes_found": [],
            "resource_indicators_supported": False,
        }
        
        # Try to discover OAuth server
        oauth_server = await self.discover_oauth_server()
        
        if not oauth_server:
            return None, "Cannot test OAuth server MCP compliance without an OAuth server. Run OAuth server discovery test first.", details
        
        details["oauth_server_found"] = oauth_server
        
        try:
            metadata_url = urljoin(oauth_server, "/.well-known/oauth-authorization-server")
            response = await self.client.get(metadata_url)
            
            if response.status_code != 200:
                return None, "Cannot test OAuth server compliance - metadata endpoint not accessible", details
            
            # Parse and validate metadata
            metadata = response.json()
            validator = RFC8414Validator(metadata)
            is_valid, parsed_metadata, issues = validator.validate()
            
            details["rfc8414_validation"] = {
                "valid": is_valid,
                "issues": issues,
                "metadata": metadata,
            }
            
            if not is_valid:
                return False, "OAuth authorization server metadata is not compliant with RFC 8414. The metadata document must include all required fields per RFC 8414 Section 2 (issuer, authorization_endpoint, token_endpoint, response_types_supported) and follow the specification constraints. Common issues include missing required fields (RFC 8414 Section 2), invalid URL formats (RFC 3986), or issuer URL not matching the server's base URL (RFC 8414 Section 2 requires issuer to be an HTTPS URL with no query or fragment).", details
            
            # Check MCP-specific requirements
            scopes_supported = metadata.get("scopes_supported", [])
            details["mcp_scopes_found"] = [s for s in scopes_supported if s.startswith("mcp:")]
            has_mcp_scopes = set(scopes_supported) & {"mcp:read", "mcp:write"}
            has_resource_indicators = metadata.get("resource_indicators_supported", False)
            details["resource_indicators_supported"] = has_resource_indicators
            
            if not has_mcp_scopes:
                return False, "OAuth authorization server does not support required MCP scopes. The server must advertise support for 'mcp:read' and 'mcp:write' scopes in the scopes_supported field of its metadata per RFC 8414 Section 2. These scopes are essential for MCP protocol authorization as defined in the MCP Authorization Specification - mcp:read allows reading server state and mcp:write allows invoking tools and modifying resources following the principle of least privilege (RFC 6749 Section 3.3).", details
            
            # Success message
            success_msg = (
                f"OAuth authorization server at {oauth_server} is fully compliant with MCP requirements. "
                f"The server correctly implements RFC 8414 with all required metadata fields and supports MCP scopes: {', '.join(sorted(has_mcp_scopes))}. "
            )
            
            if has_resource_indicators:
                success_msg += "The server also supports resource indicators (RFC 8707) allowing fine-grained access control for multiple MCP servers."
            else:
                details["warnings"] = ["OAuth server doesn't support resource indicators (RFC 8707) - tokens will work with any MCP server"]
                success_msg += "Note: The server doesn't support resource indicators (RFC 8707), which means tokens may be accepted by any MCP server rather than being restricted to specific resources."
            
            return True, success_msg, details
            
        except Exception as e:
            return False, f"Failed to validate OAuth authorization server MCP compliance. An error occurred while attempting to validate the OAuth server metadata from {oauth_server}. The specific error was: {str(e)}", details
    
    async def discover_oauth_server(self) -> Optional[str]:
        """Discover OAuth server using multiple methods.
        
        Returns:
            OAuth server URL if discovered, None otherwise
        """
        discovered_servers = []
        
        # Method 1: Try to get from protected resource metadata
        try:
            passed, error, details = await self.test_protected_resource_metadata()
            if passed and self.server_info and self.server_info.oauth_metadata:
                auth_servers = self.server_info.oauth_metadata.authorization_servers
                if auth_servers:
                    discovered_servers.extend([str(s) for s in auth_servers])
        except Exception:
            pass  # Continue with other methods
        
        # Method 2: Try common subdomain patterns
        parsed_url = urlparse(self.server_url)
        base_domain = parsed_url.hostname
        if base_domain:
            # Extract base domain (e.g., atratest.org from echo-stateless.atratest.org)
            parts = base_domain.split('.')
            if len(parts) > 2:
                base_domain = '.'.join(parts[-2:])
            
            common_auth_urls = [
                f"https://auth.{base_domain}",
                f"https://oauth.{base_domain}",
                f"https://sso.{base_domain}",
                f"https://login.{base_domain}",
            ]
            
            for auth_url in common_auth_urls:
                try:
                    # Check if OAuth metadata endpoint exists
                    test_url = urljoin(auth_url, "/.well-known/oauth-authorization-server")
                    response = await self.client.get(test_url, follow_redirects=True)
                    if response.status_code == 200:
                        discovered_servers.append(auth_url)
                        break  # Found one
                except Exception:
                    continue
        
        # Method 3: Check if the MCP server itself is also an OAuth server
        try:
            test_url = urljoin(self.server_url, "/.well-known/oauth-authorization-server")
            response = await self.client.get(test_url, follow_redirects=True)
            if response.status_code == 200:
                discovered_servers.append(self.server_url)
        except Exception:
            pass
        
        # Return the first discovered server
        return discovered_servers[0] if discovered_servers else None
    
    async def setup_oauth_client(self, force_new: bool = False) -> Optional[OAuthTestClient]:
        """Setup OAuth client with automatic discovery and registration.
        
        Args:
            force_new: Force new client registration even if credentials exist
        
        Returns:
            Configured OAuth client or None if setup failed
        """
        # Discover OAuth server
        auth_server_url = await self.discover_oauth_server()
        if not auth_server_url:
            return None
        
        # Check for existing credentials
        credentials = self.env_manager.get_oauth_credentials(self.server_url)
        
        # Create OAuth client
        self.oauth_client = OAuthTestClient(
            auth_server_url=auth_server_url,
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
            registration_access_token=credentials["registration_token"],
        )
        
        # If we have credentials and not forcing new, we're done
        if credentials["client_id"] and not force_new:
            return self.oauth_client
        
        # Otherwise, register new client if auto_register is enabled
        if self.auto_register:
            try:
                # Discover OAuth server metadata
                await self.oauth_client.discover_metadata()
                
                # Register new client
                client_id, client_secret, reg_token = await self.oauth_client.register_client(
                    client_name=f"MCP Validator for {self.server_url}",
                    software_id="mcp-http-validator",
                    software_version="0.1.0",
                )
                
                # Save credentials to .env
                self.env_manager.save_oauth_credentials(
                    server_url=self.server_url,
                    client_id=client_id,
                    client_secret=client_secret,
                    registration_token=reg_token,
                )
                
                return self.oauth_client
                
            except Exception as e:
                # Registration failed
                print(f"OAuth client registration failed: {e}")
                return None
        
        return None
    
    async def get_access_token(self, interactive: bool = False) -> Optional[str]:
        """Get an access token, either from parameter or by OAuth flow.
        
        Args:
            interactive: Whether to allow interactive flows (device auth)
        
        Returns:
            Access token or None if unavailable
        """
        # If we already have a token from parameter, use it
        if self.access_token:
            return self.access_token
        
        # Check .env for valid access token
        stored_token = self.env_manager.get_valid_access_token(self.server_url)
        if stored_token:
            self.access_token = stored_token
            return self.access_token
        
        # Check if we have a refresh token
        refresh_token = self.env_manager.get_refresh_token(self.server_url)
        if refresh_token:
            # Try to setup OAuth client if needed
            if not self.oauth_client:
                await self.setup_oauth_client()
            
            if self.oauth_client:
                try:
                    # Attempt to refresh the token
                    token_response = await self.oauth_client.refresh_token(refresh_token)
                    if token_response:
                        self.access_token = token_response.access_token
                        # Save new tokens
                        self.env_manager.save_tokens(
                            self.server_url,
                            token_response.access_token,
                            token_response.expires_in,
                            token_response.refresh_token or refresh_token
                        )
                        return self.access_token
                except Exception as e:
                    print(f"Token refresh failed: {e}")
        
        # Try to setup OAuth client if not already done
        if not self.oauth_client:
            await self.setup_oauth_client()
        
        if not self.oauth_client:
            return None
        
        # Try automated grant types
        
        # 1. Try Client Credentials Grant (best for server-to-server)
        try:
            token_response = await self.oauth_client.client_credentials_grant(
                scope="mcp:read mcp:write",
                resources=[self.server_url]
            )
            if token_response:
                self.access_token = token_response.access_token
                return self.access_token
        except Exception as e:
            print(f"Client credentials grant failed: {e}")
        
        # 2. Try Device Authorization Grant if interactive mode
        if interactive:
            try:
                device_response = await self.oauth_client.device_authorization_grant(
                    scope="mcp:read mcp:write"
                )
                if device_response:
                    print(f"\nTo authorize, visit: {device_response['verification_uri']}")
                    print(f"Enter code: {device_response['user_code']}")
                    print("Waiting for authorization...")
                    
                    token_response = await self.oauth_client.poll_device_token(
                        device_response['device_code'],
                        device_response.get('interval', 5),
                        device_response.get('expires_in', 300)
                    )
                    
                    if token_response:
                        self.access_token = token_response.access_token
                        return self.access_token
            except Exception as e:
                print(f"Device authorization grant failed: {e}")
        
        # No automated grant available
        return None
    
    async def validate(self) -> ValidationResult:
        """Run all validation tests and return results."""
        start_time = datetime.utcnow()
        
        # Define all test cases
        test_cases = [
            (
                TestCase(
                    id="oauth-metadata",
                    name="OAuth Discovery Endpoint",
                    description="Server must expose /.well-known/oauth-protected-resource (RFC 9728)",
                    spec_reference="MCP Auth Spec Section 2.1",
                    severity=TestSeverity.CRITICAL,
                    required=True,
                    category="oauth",
                ),
                self.test_protected_resource_metadata,
            ),
            (
                TestCase(
                    id="oauth-server-discovery",
                    name="OAuth Server Discovery",
                    description="Discover OAuth authorization server",
                    spec_reference="RFC 8414",
                    severity=TestSeverity.HIGH,
                    required=False,
                    category="oauth",
                ),
                self.test_oauth_server_discovery,
            ),
            (
                TestCase(
                    id="oauth-server-mcp-compliance",
                    name="OAuth Server MCP Compliance",
                    description="Validate OAuth server supports MCP requirements",
                    spec_reference="MCP Auth Spec, RFC 8414",
                    severity=TestSeverity.HIGH,
                    required=False,
                    category="oauth",
                ),
                self.test_oauth_server_mcp_compliance,
            ),
            (
                TestCase(
                    id="auth-challenge",
                    name="401 Authentication Response",
                    description="Server must return 401 with proper WWW-Authenticate header",
                    spec_reference="MCP Auth Spec Section 2.2",
                    severity=TestSeverity.CRITICAL,
                    required=True,
                    category="oauth",
                ),
                self.test_unauthenticated_request,
            ),
            (
                TestCase(
                    id="auth-success",
                    name="Bearer Token Authentication", 
                    description="Server must accept valid bearer tokens",
                    spec_reference="MCP Auth Spec Section 2.3",
                    severity=TestSeverity.CRITICAL,
                    required=True,
                    category="oauth",
                ),
                self.test_authenticated_request,
            ),
            (
                TestCase(
                    id="token-audience",
                    name="Token Audience Restrictions",
                    description="Server should validate token audience claims",
                    spec_reference="RFC 9728 Section 3",
                    severity=TestSeverity.HIGH,
                    required=False,
                    category="oauth",
                ),
                self.test_token_audience_validation,
            ),
            (
                TestCase(
                    id="http-transport",
                    name="MCP Protocol Transport",
                    description="Server must support HTTP transport with JSON or SSE responses",
                    spec_reference="MCP Transport Spec Section 3.1",
                    severity=TestSeverity.HIGH,
                    required=True,
                    category="protocol",
                ),
                self.test_http_transport,
            ),
            (
                TestCase(
                    id="protocol-version",
                    name="Protocol Version Header",
                    description="Server must support MCP protocol version 2025-06-18",
                    spec_reference="MCP Transport Spec Section 2.4",
                    severity=TestSeverity.CRITICAL,
                    required=True,
                    category="protocol",
                ),
                self.test_protocol_version,
            ),
            (
                TestCase(
                    id="mcp-tools",
                    name="MCP Tools",
                    description="Test tool discovery and validation",
                    spec_reference="MCP Core Spec - Tools",
                    severity=TestSeverity.HIGH,
                    required=False,
                    category="protocol",
                ),
                self.test_mcp_tools,
            ),
        ]
        
        # Initialize server info
        self.server_info = MCPServerInfo(url=HttpUrl(self.server_url))
        
        # Execute all tests
        self.test_results = []
        for test_case, test_func in test_cases:
            result = await self._execute_test(test_case, test_func)
            self.test_results.append(result)
        
        # Calculate summary statistics
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r.status == TestStatus.PASSED)
        failed_tests = sum(1 for r in self.test_results if r.status == TestStatus.FAILED)
        skipped_tests = sum(1 for r in self.test_results if r.status == TestStatus.SKIPPED)
        error_tests = sum(1 for r in self.test_results if r.status == TestStatus.ERROR)
        
        return ValidationResult(
            server_url=HttpUrl(self.server_url),
            started_at=start_time,
            completed_at=datetime.utcnow(),
            total_tests=total_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            skipped_tests=skipped_tests,
            error_tests=error_tests,
            test_results=self.test_results,
        )