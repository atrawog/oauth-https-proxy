"""Configuration models for MCP verification tools."""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, HttpUrl


class TestConfig(BaseModel):
    """Configuration for test execution."""
    
    # Endpoint configuration
    endpoint: HttpUrl = Field(description="MCP endpoint URL to test")
    timeout: int = Field(30, description="Default timeout for tests in seconds")
    max_retries: int = Field(3, description="Maximum retries for failed requests")
    
    # Test selection
    categories: Optional[List[str]] = Field(None, description="Categories to test")
    tags: Optional[List[str]] = Field(None, description="Tags to filter tests")
    test_ids: Optional[List[str]] = Field(None, description="Specific test IDs to run")
    skip_tests: Optional[List[str]] = Field(None, description="Test IDs to skip")
    
    # Execution options
    parallel: bool = Field(True, description="Run tests in parallel")
    fail_fast: bool = Field(False, description="Stop on first critical failure")
    verbose: bool = Field(False, description="Verbose output")
    strict: bool = Field(False, description="Fail on any non-compliance")
    
    # Performance testing
    stress_test: bool = Field(False, description="Run stress tests")
    concurrent_sessions: int = Field(50, description="Number of concurrent sessions for stress testing")
    stress_duration: int = Field(60, description="Stress test duration in seconds")
    
    # Reporting
    output_format: str = Field("yaml", description="Output format (yaml/json/html/markdown)")
    output_path: Optional[str] = Field(None, description="Output file path")
    include_passing: bool = Field(False, description="Include passing tests in report")
    include_evidence: bool = Field(True, description="Include evidence in report")
    
    # Authentication (if required)
    auth_token: Optional[str] = Field(None, description="Authentication token if required")
    auth_header: str = Field("Authorization", description="Authentication header name")
    
    # Advanced options
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Custom headers to send")
    verify_ssl: bool = Field(True, description="Verify SSL certificates")
    proxy: Optional[str] = Field(None, description="HTTP proxy to use")
    
    class Config:
        """Pydantic configuration."""
        json_schema_extra = {
            "example": {
                "endpoint": "https://everything.atratest.org/mcp",
                "categories": ["session", "transport"],
                "parallel": True,
                "output_format": "yaml",
                "output_path": "mcp-compliance-report.yaml"
            }
        }