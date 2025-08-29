"""Base test class with common functionality for MCP tests."""

import json
import time
from abc import ABC
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import httpx
from pydantic import ValidationError, BaseModel

from ..models.test_results import TestResult, TestStatus, Evidence, PerformanceMetrics


class MCPTestBase(ABC):
    """
    Base class for all MCP tests with common functionality.
    
    This class provides utilities for:
    - Session management
    - Request/response handling
    - Evidence collection
    - Schema validation
    - Common validation checks
    """
    
    def __init__(self, endpoint: str, client: Optional[httpx.AsyncClient] = None):
        """
        Initialize the test base.
        
        Args:
            endpoint: MCP endpoint URL
            client: Optional httpx client (will create one if not provided)
        """
        self.endpoint = endpoint
        # Disable httpx logging to reduce noise
        import logging
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        self.client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=False
        )
        self.session_id: Optional[str] = None
        self.evidence = Evidence()
        self.metrics = PerformanceMetrics()
        self._request_count = 0
        self._start_time = None
    
    async def initialize_session(self, 
                                protocol_version: str = "2025-06-18",
                                capabilities: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Initialize MCP session with proper error handling.
        
        Args:
            protocol_version: MCP protocol version to use
            capabilities: Client capabilities to advertise
        
        Returns:
            Initialize response result
        
        Raises:
            Exception: If initialization fails
        """
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": capabilities or {},
                "clientInfo": {
                    "name": "mcp-verification-tools",
                    "version": "1.0.0"
                }
            }
        }
        
        self.evidence.request_sent = request
        
        try:
            # Send the request, but we need access to headers
            # Store the original response
            response = await self.send_request(request)
            
            # Check for session ID in headers (MCP spec allows this)
            if self.evidence.headers and 'mcp-session-id' in self.evidence.headers:
                self.session_id = self.evidence.headers['mcp-session-id']
            elif self.evidence.headers and 'Mcp-Session-Id' in self.evidence.headers:
                self.session_id = self.evidence.headers['Mcp-Session-Id']
            
            # Check response
            if response.get("result"):
                result = response["result"]
                # Also check for sessionId in result (some servers might put it here)
                if not self.session_id:
                    self.session_id = result.get("sessionId")
                return result
            elif response.get("error"):
                raise Exception(f"Initialize failed: {response['error']}")
            else:
                raise Exception("Invalid initialize response format")
                
        except Exception as e:
            self.evidence.error_details = str(e)
            raise
    
    async def send_request(self, 
                          request: Dict[str, Any],
                          headers: Optional[Dict[str, str]] = None,
                          measure_time: bool = True) -> Dict[str, Any]:
        """
        Send a JSON-RPC request to the MCP endpoint.
        
        Args:
            request: JSON-RPC request object
            headers: Optional additional headers
            measure_time: Whether to measure response time
        
        Returns:
            JSON-RPC response
        """
        # Prepare headers - MCP requires both SSE and JSON in Accept header
        request_headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream, application/json",  # MCP requirement
            "MCP-Protocol-Version": "2025-06-18"  # Add protocol version
        }
        
        # Add session ID if available
        if self.session_id:
            request_headers["Mcp-Session-Id"] = self.session_id
        
        # Add custom headers
        if headers:
            request_headers.update(headers)
        
        # Measure time if requested
        start_time = time.perf_counter() if measure_time else None
        
        try:
            # Send request
            response = await self.client.post(
                self.endpoint,
                json=request,
                headers=request_headers
            )
            
            # Record timing
            if measure_time:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                if not self.metrics.response_time_ms:
                    self.metrics.response_time_ms = elapsed_ms
                else:
                    # Keep average
                    self.metrics.response_time_ms = (
                        self.metrics.response_time_ms + elapsed_ms
                    ) / 2
            
            # Record evidence
            self.evidence.headers = dict(response.headers)
            self._request_count += 1
            
            # Parse response based on content type
            content_type = response.headers.get('content-type', '').lower()
            
            if response.status_code == 202:
                # Accepted - might be async response
                return {"status": "accepted", "headers": dict(response.headers)}
            elif response.status_code == 200:
                # Check if response is SSE or JSON
                if 'text/event-stream' in content_type:
                    # Parse SSE response - look for data lines
                    lines = response.text.strip().split('\n')
                    for line in lines:
                        if line.startswith('data: '):
                            try:
                                data = json.loads(line[6:])  # Skip "data: " prefix
                                self.evidence.response_received = data
                                return data
                            except json.JSONDecodeError:
                                continue
                    # No valid JSON data found in SSE
                    self.evidence.error_details = f"No valid JSON in SSE response: {response.text[:500]}"
                    raise Exception("No valid JSON data found in SSE response")
                else:
                    # Try to parse as JSON
                    try:
                        response_data = response.json()
                        self.evidence.response_received = response_data
                        return response_data
                    except json.JSONDecodeError as e:
                        # Log the actual response for debugging
                        self.evidence.error_details = f"Invalid JSON response: {response.text[:500]}"
                        raise Exception(f"Invalid JSON response from server: {e}")
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                self.evidence.error_details = error_msg
                raise Exception(error_msg)
                
        except httpx.TimeoutException:
            self.evidence.error_details = "Request timeout"
            raise
        except Exception as e:
            if not self.evidence.error_details:
                self.evidence.error_details = str(e)
            raise
    
    async def send_sse_request(self, headers: Optional[Dict[str, str]] = None):
        """
        Send a GET request to establish SSE connection.
        
        Args:
            headers: Optional additional headers
        
        Returns:
            Response object for SSE streaming
        """
        request_headers = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "MCP-Protocol-Version": "2025-06-18"  # Add protocol version
        }
        
        if self.session_id:
            request_headers["Mcp-Session-Id"] = self.session_id
        
        if headers:
            request_headers.update(headers)
        
        try:
            # Use stream=True for SSE
            async with self.client.stream("GET", self.endpoint, headers=request_headers) as response:
                return response
        except Exception as e:
            self.evidence.error_details = str(e)
            raise
    
    def validate_with_schema(self, 
                            data: Dict[str, Any], 
                            model_class: type[BaseModel]) -> Tuple[Optional[BaseModel], Optional[str]]:
        """
        Validate data against a Pydantic model.
        
        Args:
            data: Data to validate
            model_class: Pydantic model class
        
        Returns:
            Tuple of (validated model or None, error message or None)
        """
        try:
            validated = model_class(**data)
            return validated, None
        except ValidationError as e:
            return None, str(e)
    
    def check_character_range(self, 
                             text: str, 
                             min_ord: int, 
                             max_ord: int) -> List[Dict[str, Any]]:
        """
        Check if all characters in text are within specified ASCII range.
        
        Args:
            text: Text to check
            min_ord: Minimum ASCII value (inclusive)
            max_ord: Maximum ASCII value (inclusive)
        
        Returns:
            List of violations with position and character details
        """
        violations = []
        
        for i, char in enumerate(text):
            char_code = ord(char)
            if not (min_ord <= char_code <= max_ord):
                violations.append({
                    'position': i,
                    'character': char,
                    'hex': hex(char_code),
                    'decimal': char_code,
                    'description': self.describe_character(char)
                })
        
        return violations
    
    def describe_character(self, char: str) -> str:
        """
        Get a human-readable description of a character.
        
        Args:
            char: Character to describe
        
        Returns:
            Description string
        """
        char_code = ord(char)
        
        if char_code == 0x20:
            return "space"
        elif char_code == 0x09:
            return "tab"
        elif char_code == 0x0A:
            return "newline (LF)"
        elif char_code == 0x0D:
            return "carriage return (CR)"
        elif char_code < 0x20:
            return f"control character (0x{char_code:02X})"
        elif char_code > 0x7E:
            return f"extended ASCII (0x{char_code:02X})"
        else:
            return f"'{char}'"
    
    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.
        
        Args:
            text: Text to analyze
        
        Returns:
            Entropy in bits per character
        """
        import math
        from collections import Counter
        
        if not text:
            return 0.0
        
        # Count character frequencies
        counts = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def create_test_result(self, 
                          test_id: str,
                          test_name: str = "",
                          category: str = "",
                          severity: str = "MEDIUM") -> TestResult:
        """
        Create a test result with common fields populated.
        
        Args:
            test_id: Test identifier
            test_name: Test name
            category: Test category
            severity: Test severity
        
        Returns:
            TestResult instance
        """
        return TestResult(
            test_id=test_id,
            test_name=test_name,
            category=category,
            severity=severity,
            status=TestStatus.PENDING,
            evidence=self.evidence if self.evidence.request_sent else None,
            metrics=self.metrics if self._request_count > 0 else None,
            started_at=datetime.utcnow()
        )
    
    def format_violations(self, violations: List[Dict[str, Any]]) -> str:
        """
        Format character violations into a readable string.
        
        Args:
            violations: List of violation dictionaries
        
        Returns:
            Formatted string describing violations
        """
        if not violations:
            return "No violations found"
        
        lines = []
        for v in violations:
            lines.append(
                f"Position {v['position']}: {v['description']} "
                f"(hex: {v['hex']}, decimal: {v['decimal']})"
            )
        
        return "\n".join(lines)
    
    def get_safe_session_id_example(self) -> str:
        """
        Get example code for generating safe session IDs.
        
        Returns:
            Python code example
        """
        return '''
# Example: Generating MCP-compliant session IDs
import secrets
import string

# Safe character set (visible ASCII minus problematic chars)
# Using alphanumeric plus hyphen and underscore for maximum compatibility
SAFE_CHARS = string.ascii_letters + string.digits + "-_"

def generate_session_id(length: int = 32) -> str:
    """Generate a cryptographically secure session ID."""
    return ''.join(secrets.choice(SAFE_CHARS) for _ in range(length))

# Alternative: Using UUID
import uuid

def generate_uuid_session() -> str:
    """Generate session ID using UUID (no hyphens for simplicity)."""
    return str(uuid.uuid4()).replace('-', '')
'''
    
    async def cleanup(self):
        """Clean up resources (close client, etc)."""
        if self.client:
            await self.client.aclose()
    
    def __repr__(self) -> str:
        """String representation."""
        return f"MCPTestBase(endpoint={self.endpoint}, session_id={self.session_id})"