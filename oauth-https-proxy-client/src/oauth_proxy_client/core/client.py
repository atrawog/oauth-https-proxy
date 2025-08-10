"""HTTP client for OAuth HTTPS Proxy API interactions."""

import asyncio
import json
from typing import Optional, Dict, Any, List, Union, AsyncIterator
from urllib.parse import urljoin, urlencode
import httpx
from httpx import Response, HTTPError, TimeoutException, ConnectError
from rich.console import Console

from .config import Config
from .exceptions import (
    APIError,
    AuthenticationError,
    ConnectionError,
    ResourceNotFoundError,
    TimeoutError,
    RateLimitError,
    ValidationError,
)

console = Console()


class ProxyClient:
    """HTTP client for interacting with OAuth HTTPS Proxy API.
    
    This client provides a high-level interface for all API operations
    with automatic authentication, retries, and error handling.
    """
    
    def __init__(self, config: Optional[Config] = None, dry_run: bool = False):
        """Initialize the proxy client.
        
        Args:
            config: Configuration object (creates default if not provided)
            dry_run: If True, show what would be done without making changes
        """
        self.config = config or Config.from_env()
        self.dry_run = dry_run
        self._client: Optional[httpx.AsyncClient] = None
        self._sync_client: Optional[httpx.Client] = None
    
    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client.
        
        Returns:
            Configured async HTTP client
        """
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.api_url,
                headers=self.config.get_headers(),
                timeout=httpx.Timeout(
                    connect=self.config.connect_timeout,
                    read=self.config.request_timeout,
                    write=self.config.request_timeout,
                    pool=self.config.request_timeout,
                ),
                follow_redirects=True,
                verify=True,  # Always verify SSL certificates
            )
        return self._client
    
    @property
    def sync_client(self) -> httpx.Client:
        """Get or create synchronous HTTP client.
        
        Returns:
            Configured synchronous HTTP client
        """
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                base_url=self.config.api_url,
                headers=self.config.get_headers(),
                timeout=httpx.Timeout(
                    connect=self.config.connect_timeout,
                    read=self.config.request_timeout,
                    write=self.config.request_timeout,
                    pool=self.config.request_timeout,
                ),
                follow_redirects=True,
                verify=True,
            )
        return self._sync_client
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    def __enter__(self):
        """Sync context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Sync context manager exit."""
        self.close_sync()
    
    async def close(self):
        """Close the async HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def close_sync(self):
        """Close the sync HTTP client."""
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None
    
    def _handle_response_error(self, response: Response):
        """Handle HTTP error responses.
        
        Args:
            response: HTTP response object
        
        Raises:
            Various exceptions based on status code
        """
        status = response.status_code
        
        # Try to get error details from response
        try:
            error_data = response.json()
            message = error_data.get('detail', str(error_data))
        except (json.JSONDecodeError, KeyError):
            message = response.text or f"HTTP {status} error"
        
        # Handle specific status codes
        if status == 401:
            raise AuthenticationError(message)
        elif status == 403:
            raise AuthenticationError(f"Permission denied: {message}")
        elif status == 404:
            # Try to extract resource type from URL
            path_parts = response.request.url.path.strip('/').split('/')
            resource_type = path_parts[2] if len(path_parts) > 2 else "resource"
            resource_id = path_parts[-1] if len(path_parts) > 0 else "unknown"
            raise ResourceNotFoundError(resource_type, resource_id)
        elif status == 422:
            # Validation error
            if isinstance(error_data, dict):
                details = error_data.get('detail', [])
                if isinstance(details, list) and details:
                    error = details[0]
                    field = '.'.join(error.get('loc', ['unknown']))
                    msg = error.get('msg', 'Validation failed')
                    raise ValidationError(field, msg)
            raise ValidationError('request', message)
        elif status == 429:
            retry_after = response.headers.get('Retry-After')
            raise RateLimitError(int(retry_after) if retry_after else None)
        elif status >= 500:
            raise APIError(f"Server error: {message}", status_code=status, response_text=response.text)
        else:
            raise APIError(message, status_code=status, response_text=response.text)
    
    async def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        stream: bool = False,
    ) -> Union[Response, AsyncIterator[bytes]]:
        """Make an async HTTP request.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: API endpoint path
            params: Query parameters
            json_data: JSON body data
            data: Form data
            headers: Additional headers
            files: Files to upload
            stream: Whether to stream the response
        
        Returns:
            HTTP response or async iterator for streaming
        
        Raises:
            Various exceptions based on response
        """
        # Ensure path has trailing slash for collection endpoints
        if method == 'GET' and path.endswith(('tokens', 'certificates', 'routes', 'services', 'resources', 'targets')):
            if not path.endswith('/'):
                path += '/'
        
        # Build full URL
        url = urljoin(self.config.api_url, path)
        
        # Merge headers
        request_headers = self.config.get_headers()
        if headers:
            request_headers.update(headers)
        
        try:
            if stream:
                # Return streaming response
                return self.client.stream(
                    method,
                    url,
                    params=params,
                    json=json_data,
                    data=data,
                    headers=request_headers,
                    files=files,
                )
            else:
                # Make regular request
                response = await self.client.request(
                    method,
                    url,
                    params=params,
                    json=json_data,
                    data=data,
                    headers=request_headers,
                    files=files,
                )
                
                # Check for errors
                if response.status_code >= 400:
                    self._handle_response_error(response)
                
                return response
                
        except TimeoutException as e:
            raise TimeoutError(f"{method} {path}", self.config.request_timeout)
        except ConnectError as e:
            raise ConnectionError(url, str(e))
        except HTTPError as e:
            raise APIError(f"HTTP error: {str(e)}")
    
    def request_sync(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
    ) -> Response:
        """Make a synchronous HTTP request.
        
        Args:
            method: HTTP method
            path: API endpoint path
            params: Query parameters
            json_data: JSON body data
            data: Form data
            headers: Additional headers
            files: Files to upload
        
        Returns:
            HTTP response
        
        Raises:
            Various exceptions based on response
        """
        # Ensure path has trailing slash for collection endpoints
        if method == 'GET' and path.endswith(('tokens', 'certificates', 'routes', 'services', 'resources', 'targets')):
            if not path.endswith('/'):
                path += '/'
        
        # Build full URL
        url = urljoin(self.config.api_url, path)
        
        # Merge headers
        request_headers = self.config.get_headers()
        if headers:
            request_headers.update(headers)
        
        try:
            response = self.sync_client.request(
                method,
                url,
                params=params,
                json=json_data,
                data=data,
                headers=request_headers,
                files=files,
            )
            
            # Check for errors
            if response.status_code >= 400:
                self._handle_response_error(response)
            
            return response
            
        except TimeoutException as e:
            raise TimeoutError(f"{method} {path}", self.config.request_timeout)
        except ConnectError as e:
            raise ConnectionError(url, str(e))
        except HTTPError as e:
            raise APIError(f"HTTP error: {str(e)}")
    
    # Convenience methods for common operations
    
    async def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a GET request and return JSON response.
        
        Args:
            path: API endpoint path
            params: Query parameters
        
        Returns:
            JSON response as dictionary
        """
        response = await self.request('GET', path, params=params)
        return response.json()
    
    async def post(self, path: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a POST request and return JSON response.
        
        Args:
            path: API endpoint path
            json_data: Request body data
        
        Returns:
            JSON response as dictionary
        """
        response = await self.request('POST', path, json_data=json_data)
        if response.status_code == 204:
            return {}
        return response.json()
    
    async def put(self, path: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a PUT request and return JSON response.
        
        Args:
            path: API endpoint path
            json_data: Request body data
        
        Returns:
            JSON response as dictionary
        """
        response = await self.request('PUT', path, json_data=json_data)
        if response.status_code == 204:
            return {}
        return response.json()
    
    async def delete(self, path: str) -> bool:
        """Make a DELETE request.
        
        Args:
            path: API endpoint path
        
        Returns:
            True if successful
        """
        response = await self.request('DELETE', path)
        return response.status_code in (200, 204)
    
    def get_sync(self, path: str, params: Optional[Dict[str, Any]] = None) -> Union[Dict[str, Any], str]:
        """Make a synchronous GET request.
        
        Args:
            path: API endpoint path
            params: Query parameters
        
        Returns:
            JSON response as dictionary or text for formatted endpoints
        """
        response = self.request_sync('GET', path, params=params)
        
        # Check if this is a formatted endpoint that returns text
        if path.endswith('/formatted'):
            return response.text
        
        # Check content-type header
        content_type = response.headers.get('content-type', '')
        if 'application/json' in content_type:
            return response.json()
        else:
            # Return text for non-JSON responses
            return response.text
    
    def post_sync(self, path: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a synchronous POST request.
        
        Args:
            path: API endpoint path
            json_data: Request body data
        
        Returns:
            JSON response as dictionary
        """
        if self.dry_run:
            console.print(f"[yellow]DRY RUN: Would POST to {path}[/yellow]")
            if json_data:
                console.print(f"[dim]Data: {json.dumps(json_data, indent=2)}[/dim]")
            return {"dry_run": True, "action": "POST", "path": path}
        
        response = self.request_sync('POST', path, json_data=json_data)
        if response.status_code == 204:
            return {}
        return response.json()
    
    def put_sync(self, path: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a synchronous PUT request.
        
        Args:
            path: API endpoint path
            json_data: Request body data
        
        Returns:
            JSON response as dictionary
        """
        if self.dry_run:
            console.print(f"[yellow]DRY RUN: Would PUT to {path}[/yellow]")
            if json_data:
                console.print(f"[dim]Data: {json.dumps(json_data, indent=2)}[/dim]")
            return {"dry_run": True, "action": "PUT", "path": path}
        
        response = self.request_sync('PUT', path, json_data=json_data)
        if response.status_code == 204:
            return {}
        return response.json()
    
    def delete_sync(self, path: str) -> bool:
        """Make a synchronous DELETE request.
        
        Args:
            path: API endpoint path
        
        Returns:
            True if successful
        """
        if self.dry_run:
            console.print(f"[yellow]DRY RUN: Would DELETE {path}[/yellow]")
            return True
        
        response = self.request_sync('DELETE', path)
        return response.status_code in (200, 204)
    
    # WebSocket support for real-time features
    
    async def websocket(self, path: str) -> httpx.AsyncClient:
        """Create a WebSocket connection.
        
        Args:
            path: WebSocket endpoint path
        
        Returns:
            WebSocket client
        
        Note:
            This returns the httpx client configured for WebSocket.
            For actual WebSocket support, use the websockets library separately.
        """
        # WebSocket URL (convert http to ws)
        ws_url = self.config.api_url.replace('http://', 'ws://').replace('https://', 'wss://')
        ws_url = urljoin(ws_url, path)
        
        # Return configured client (actual WebSocket handled by websockets library)
        return self.client
    
    # Health check
    
    async def health_check(self) -> bool:
        """Check if the API is healthy.
        
        Returns:
            True if API is healthy
        """
        try:
            response = await self.request('GET', '/health')
            return response.status_code == 200
        except Exception:
            return False
    
    def health_check_sync(self) -> bool:
        """Synchronous health check.
        
        Returns:
            True if API is healthy
        """
        try:
            response = self.request_sync('GET', '/health')
            return response.status_code == 200
        except Exception:
            return False