"""Unified handler for OAuth metadata endpoints (authorization server and protected resource)."""

import logging
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException
from ...shared.client_ip import get_real_client_ip
from ...shared.logger import log_debug, log_info, log_warning, log_error, log_trace




class OAuthMetadataHandler:
    """Handles both OAuth authorization server and protected resource metadata endpoints."""
    
    def __init__(self, settings, storage):
        """Initialize metadata handler.
        
        Args:
            settings: OAuth settings with defaults
            storage: Storage backend for proxy configurations
        """
        self.settings = settings
        self.storage = storage
    
    def get_external_url(self, request: Request, hostname: Optional[str] = None) -> str:
        """Get the external URL for a service from request headers.
        
        Args:
            request: FastAPI request object
            hostname: Optional hostname override
            
        Returns:
            External URL for the service
        """
        # Use provided hostname or get from headers
        if not hostname:
            hostname = request.headers.get("x-forwarded-host") or request.headers.get("host", f"auth.{self.settings.base_domain}")
            if ":" in hostname:
                hostname = hostname.split(":")[0]
        
        # Get protocol from headers
        proto = request.headers.get("x-forwarded-proto") or request.url.scheme
        
        return f"{proto}://{hostname}"
    
    async def get_authorization_server_metadata(self, request: Request, hostname: Optional[str] = None) -> Dict[str, Any]:
        """Get OAuth authorization server metadata, optionally customized per proxy.
        
        Args:
            request: FastAPI request object
            hostname: Optional hostname to get proxy-specific configuration
            
        Returns:
            OAuth authorization server metadata dictionary
        """
        client_ip = get_real_client_ip(request)
        
        # If no hostname provided, try to extract from headers
        if not hostname:
            hostname = request.headers.get("x-forwarded-host", "").split(":")[0]
            if not hostname:
                hostname = request.headers.get("host", "").split(":")[0]
        
        # Default metadata
        api_url = self.get_external_url(request, hostname)
        
        metadata = {
            "issuer": api_url,
            "authorization_endpoint": f"{api_url}/authorize",
            "token_endpoint": f"{api_url}/token",
            "registration_endpoint": f"{api_url}/register",
            "jwks_uri": f"{api_url}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256", "RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "claims_supported": ["sub", "name", "email", "preferred_username", "aud", "azp"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "revocation_endpoint": f"{api_url}/revoke",
            "introspection_endpoint": f"{api_url}/introspect",
            # RFC 8707 Resource Indicators
            "resource_indicators_supported": True,
            "resource_parameter_supported": True,
            "authorization_response_iss_parameter_supported": True
        }
        
        # Check for proxy-specific configuration if hostname is provided
        if hostname and self.storage:
            try:
                proxy_target = await self.storage.get_proxy_target(hostname)
                if proxy_target and proxy_target.oauth_server_override_defaults:
                    log_info(f"Using proxy-specific OAuth server config for {hostname}")
                    
                    # Override with proxy-specific configuration
                    if proxy_target.oauth_server_issuer:
                        metadata["issuer"] = proxy_target.oauth_server_issuer
                        # Update endpoint URLs if issuer changes
                        base_url = proxy_target.oauth_server_issuer
                        metadata["authorization_endpoint"] = f"{base_url}/authorize"
                        metadata["token_endpoint"] = f"{base_url}/token"
                        metadata["registration_endpoint"] = f"{base_url}/register"
                        metadata["jwks_uri"] = f"{base_url}/jwks"
                        metadata["revocation_endpoint"] = f"{base_url}/revoke"
                        metadata["introspection_endpoint"] = f"{base_url}/introspect"
                    
                    if proxy_target.oauth_server_scopes:
                        metadata["scopes_supported"] = proxy_target.oauth_server_scopes
                    
                    if proxy_target.oauth_server_grant_types:
                        metadata["grant_types_supported"] = proxy_target.oauth_server_grant_types
                    
                    if proxy_target.oauth_server_response_types:
                        metadata["response_types_supported"] = proxy_target.oauth_server_response_types
                    
                    if proxy_target.oauth_server_token_auth_methods:
                        metadata["token_endpoint_auth_methods_supported"] = proxy_target.oauth_server_token_auth_methods
                    
                    if proxy_target.oauth_server_claims:
                        metadata["claims_supported"] = proxy_target.oauth_server_claims
                    
                    if proxy_target.oauth_server_pkce_required:
                        metadata["code_challenge_methods_supported"] = ["S256"]
                        metadata["code_challenge_methods_required"] = True
                    
                    # Add custom metadata fields
                    if proxy_target.oauth_server_custom_metadata:
                        metadata.update(proxy_target.oauth_server_custom_metadata)
                    
                    log_debug(f"OAuth server metadata customized for {hostname}")
            except Exception as e:
                log_error(f"Failed to get proxy-specific OAuth config for {hostname}: {e}")
                # Fall back to defaults on error
        
        log_info(
            "OAuth authorization server metadata requested",
            client_ip=client_ip, proxy_hostname=hostname,
            issuer=metadata.get("issuer")
        )
        
        return metadata
    
    async def get_protected_resource_metadata(self, request: Request, proxy_hostname: str) -> Dict[str, Any]:
        """Get OAuth protected resource metadata for a specific proxy.
        
        Args:
            request: FastAPI request object
            hostname: Hostname to get proxy-specific configuration
            
        Returns:
            OAuth protected resource metadata dictionary
            
        Raises:
            HTTPException: If proxy not found or metadata not configured
        """
        client_ip = get_real_client_ip(request)
        
        log_info(f"Protected resource metadata requested for {proxy_hostname} from {client_ip}")
        
        if not self.storage:
            raise HTTPException(500, "Storage not available")
        
        # Get proxy target
        target = await self.storage.get_proxy_target(proxy_hostname)
        if not target:
            log_error(f"No proxy target configured for {proxy_hostname}")
            raise HTTPException(404, f"No proxy target configured for {proxy_hostname}")
        
        # Check if protected resource metadata is configured
        if not target.resource_endpoint:
            log_warning(f"Protected resource metadata not configured for {proxy_hostname}")
            raise HTTPException(404, "Protected resource metadata not configured for this proxy")
        
        # Build resource URI
        proto = request.headers.get("x-forwarded-proto", "https")
        resource_uri = f"{proto}://{proxy_hostname}{target.resource_endpoint}"
        
        # Get authorization server URL - can be custom per proxy
        auth_servers = []
        if target.auth_enabled and target.auth_proxy:
            # Check if this proxy has custom OAuth server configuration
            auth_proxy_target = await self.storage.get_proxy_target(target.auth_proxy)
            if auth_proxy_target and auth_proxy_target.oauth_server_issuer:
                # Use custom issuer
                auth_servers.append(auth_proxy_target.oauth_server_issuer)
            else:
                # Use default
                auth_servers.append(f"https://{target.auth_proxy}")
        
        # Build metadata response per RFC 9728
        resource_scopes = target.resource_scopes or ["read", "write"]
        bearer_methods = target.resource_bearer_methods or ["header"]
        doc_suffix = target.resource_documentation_suffix or "/docs"
        
        metadata = {
            "resource": resource_uri,
            "authorization_servers": auth_servers,
            "scopes_supported": resource_scopes,
            "bearer_methods_supported": bearer_methods,
            "resource_documentation": f"{resource_uri}{doc_suffix}"
        }
        
        # Add JWKS URI if auth is enabled
        if auth_servers:
            metadata["jwks_uri"] = f"{auth_servers[0]}/jwks"
        
        # Add server info if configured
        if target.resource_server_info:
            metadata.update(target.resource_server_info)
        
        # Add custom metadata if configured
        if target.resource_custom_metadata:
            metadata.update(target.resource_custom_metadata)
        
        log_info(f"Protected resource metadata served for {proxy_hostname}")
        
        return metadata