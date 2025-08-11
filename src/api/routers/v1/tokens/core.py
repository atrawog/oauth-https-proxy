"""Core token CRUD operations with async support."""

import secrets
import logging
from datetime import datetime, timezone
from typing import List, Dict
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.responses import PlainTextResponse
import csv
import io
from tabulate import tabulate

from .models import TokenCreateRequest, TokenResponse, TokenSummary, TokenDetail
from src.api.auth import require_admin, get_current_token_info

logger = logging.getLogger(__name__)


def create_core_router(async_storage) -> APIRouter:
    """Create router for core token operations.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with core token endpoints
    """
    router = APIRouter()
    
    @router.post("/", response_model=TokenResponse)
    async def create_token(
        request: Request,
        token_request: TokenCreateRequest,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """Create a new API token."""
        # Get async async_storage if available
        async_storage = request.app.state.async_storage
        
        # Prevent creating tokens with reserved names
        if token_request.name.upper() == "ADMIN":
            raise HTTPException(400, "Cannot create token with reserved name 'ADMIN'")
        
        # Check if token name already exists
        existing = await async_storage.get_api_token_by_name(token_request.name)
        if existing:
            raise HTTPException(409, f"Token '{token_request.name}' already exists")
        
        # Generate secure token
        token_value = f"acm_{secrets.token_urlsafe(32)}"
        
        # Store token
        result = await async_storage.store_api_token(
            token_request.name, 
            token_value, 
            cert_email=token_request.cert_email
        )
        logger.info(f"Token async_storage result for '{token_request.name}': {result}")
        
        if not result:
            raise HTTPException(500, "Failed to create token")
        
        # Verify token was stored correctly
        token_data = await async_storage.get_api_token_by_name(token_request.name)
        logger.info(f"Token verification for '{token_request.name}': {token_data}")
        logger.info(f"Created token '{token_request.name}' with email {token_request.cert_email}")
        
        return TokenResponse(
            name=token_request.name,
            token=token_value,
            cert_email=token_request.cert_email,
            created_at=datetime.now(timezone.utc)
        )
    
    @router.get("/", response_model=List[TokenSummary])
    async def list_tokens(
        request: Request,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """List all API tokens."""
        # Get async async_storage if available
        async_storage = request.app.state.async_storage
        
        tokens = []
        
        # Get all token keys by scanning for name keys
        async for key in async_storage.redis_client.scan_iter(match="token:*"):
            # Decode byte string if needed
            if isinstance(key, bytes):
                key = key.decode('utf-8')
                
            # Skip if it's not a direct token key (e.g., skip token:foo:bar patterns)
            parts = key.split(":")
            if len(parts) != 2:
                continue
            token_name = parts[1]
            token_data = await async_storage.get_api_token_by_name(token_name)
                
            if token_data:
                # Count owned resources
                cert_count = await async_storage.count_certificates_by_owner(token_data['hash'])
                proxy_count = await async_storage.count_proxies_by_owner(token_data['hash'])
                    
                # Parse created_at
                created_at = datetime.now(timezone.utc)
                if 'created_at' in token_data:
                    try:
                        created_at = datetime.fromisoformat(token_data['created_at'].replace('Z', '+00:00'))
                    except:
                        pass
                    
                tokens.append(TokenSummary(
                    name=token_data['name'],
                    cert_email=token_data.get('cert_email', ''),
                    created_at=created_at,
                    certificate_count=cert_count,
                    proxy_count=proxy_count,
                    is_admin=(token_data['name'].upper() == 'ADMIN')
                ))
        # Sort by name
        tokens.sort(key=lambda t: t.name)
        return tokens
    
    @router.get("/formatted")
    async def list_tokens_formatted(
        request: Request,
        format: str = Query("table", description="Output format", enum=["table", "json", "csv"]),
        _: dict = Depends(require_admin)  # Admin only
    ):
        """List all API tokens with formatted output."""
        # Get tokens using existing endpoint logic
        tokens = await list_tokens(request, _)
        
        if format == "json":
            # Return standard JSON response
            return tokens
        
        # Prepare data for table/csv formatting
        rows = []
        for token in tokens:
            rows.append([
                token.name,
                token.cert_email or "",
                str(token.certificate_count),
                str(token.proxy_count),
                "Yes" if token.is_admin else "No",
                token.created_at.strftime("%Y-%m-%d %H:%M:%S")
            ])
        
        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Name", "Email", "Certificates", "Proxies", "Admin", "Created"])
            writer.writerows(rows)
            return PlainTextResponse(output.getvalue(), media_type="text/csv")
        
        # Default to table format
        headers = ["Name", "Email", "Certificates", "Proxies", "Admin", "Created"]
        table = tabulate(rows, headers=headers, tablefmt="grid")
        return PlainTextResponse(table, media_type="text/plain")
    
    @router.get("/{name}", response_model=TokenDetail)
    async def get_token_details(
        request: Request,
        name: str,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """Get detailed information about a specific token."""
        # Get async async_storage if available
        async_storage = request.app.state.async_storage
        
        # Get token data
        token_data = await async_storage.get_api_token_by_name(name)
        if not token_data:
            raise HTTPException(404, f"Token '{name}' not found")
        
        # Get owned resources
        certificates = await async_storage.list_certificates_by_owner(token_data['hash'])
        proxies = await async_storage.list_proxies_by_owner(token_data['hash'])
        # Parse created_at
        created_at = datetime.now(timezone.utc)
        if 'created_at' in token_data:
            try:
                created_at = datetime.fromisoformat(token_data['created_at'].replace('Z', '+00:00'))
            except:
                pass
        
        return TokenDetail(
            name=token_data['name'],
            token=token_data['token'],  # Full token value for admin
            cert_email=token_data.get('cert_email', ''),
            created_at=created_at,
            certificate_count=len(certificates),
            proxy_count=len(proxies),
            is_admin=(token_data['name'].upper() == 'ADMIN'),
            certificates=[cert.get('cert_name', '') for cert in certificates],
            proxies=[proxy.get('hostname', '') for proxy in proxies]
        )
    
    @router.delete("/{name}")
    async def delete_token(
        request: Request,
        name: str,
        cascade: bool = Query(False, description="Delete owned resources"),
        _: dict = Depends(require_admin)  # Admin only
    ):
        """Delete an API token."""
        # Get async async_storage if available
        async_storage = request.app.state.async_storage
        
        # Prevent deleting admin token
        if name.upper() == "ADMIN":
            raise HTTPException(400, "Cannot delete ADMIN token")
        
        # Get token data
        token_data = await async_storage.get_api_token_by_name(name)
        if not token_data:
            raise HTTPException(404, f"Token '{name}' not found")
        
        # Handle cascade deletion
        if cascade:
            # Delete owned certificates
            certificates = await async_storage.list_certificates_by_owner(token_data['hash'])
            for cert in certificates:
                await async_storage.delete_certificate(cert.cert_name)
                logger.info(f"Cascade deleted certificate: {cert.cert_name}")
                
            # Delete owned proxies
            proxies = await async_storage.list_proxies_by_owner(token_data['hash'])
            for proxy in proxies:
                await async_storage.delete_proxy_target(proxy.hostname)
                logger.info(f"Cascade deleted proxy: {proxy.hostname}")
        # Delete token
        result = await async_storage.delete_api_token_by_name(name)
        if not result:
            raise HTTPException(500, "Failed to delete token")
        
        logger.info(f"Deleted token '{name}'" + (" with cascade" if cascade else ""))
        
        return {
            "message": f"Token '{name}' deleted successfully",
            "cascade": cascade
        }
    
    return router