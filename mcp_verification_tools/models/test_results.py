"""Test result models for MCP compliance testing."""

from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field


class TestStatus(str, Enum):
    """Status of a test execution."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class ImpactAssessment(BaseModel):
    """Impact assessment for test failures."""
    compatibility: str = Field(description="Impact on compatibility (HIGH/MEDIUM/LOW)")
    security: str = Field(description="Security impact (CRITICAL/HIGH/MEDIUM/LOW)")
    functionality: str = Field(description="Functional impact (HIGH/MEDIUM/LOW)")
    description: str = Field(description="Detailed impact description")


class RemediationStep(BaseModel):
    """A single remediation step."""
    step: str = Field(description="Description of the remediation step")
    code_example: Optional[str] = Field(None, description="Optional code example")


class Remediation(BaseModel):
    """Remediation guidance for test failures."""
    priority: str = Field(description="Fix priority (IMMEDIATE/HIGH/MEDIUM/LOW)")
    steps: List[str] = Field(description="List of remediation steps")
    code_example: Optional[str] = Field(None, description="Code example for fix")
    estimated_effort: Optional[str] = Field(None, description="Estimated effort to fix")
    references: Optional[List[str]] = Field(None, description="Reference links")


class Evidence(BaseModel):
    """Evidence collected during test execution."""
    request_sent: Optional[Dict[str, Any]] = Field(None, description="Request sent to server")
    response_received: Optional[Dict[str, Any]] = Field(None, description="Response from server")
    headers: Optional[Dict[str, str]] = Field(None, description="HTTP headers")
    validation_details: Optional[Dict[str, Any]] = Field(None, description="Validation specifics")
    error_details: Optional[str] = Field(None, description="Error message if applicable")
    screenshots: Optional[List[str]] = Field(None, description="Base64 encoded screenshots")
    logs: Optional[List[str]] = Field(None, description="Relevant log entries")


class PerformanceMetrics(BaseModel):
    """Performance metrics collected during test."""
    response_time_ms: Optional[float] = Field(None, description="Response time in milliseconds")
    throughput_rps: Optional[float] = Field(None, description="Requests per second")
    concurrent_sessions: Optional[int] = Field(None, description="Number of concurrent sessions")
    memory_usage_mb: Optional[float] = Field(None, description="Memory usage in MB")
    cpu_usage_percent: Optional[float] = Field(None, description="CPU usage percentage")
    p50_latency_ms: Optional[float] = Field(None, description="50th percentile latency")
    p95_latency_ms: Optional[float] = Field(None, description="95th percentile latency")
    p99_latency_ms: Optional[float] = Field(None, description="99th percentile latency")
    error_rate: Optional[float] = Field(None, description="Error rate percentage")


class TestResult(BaseModel):
    """Comprehensive test result with verbose explanations."""
    
    # Basic information
    test_id: str = Field(description="Unique test identifier")
    test_name: str = Field(description="Human-readable test name")
    category: str = Field(description="Test category")
    status: TestStatus = Field(description="Test execution status")
    severity: str = Field(description="Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO)")
    
    # Timestamps
    started_at: Optional[datetime] = Field(None, description="Test start time")
    completed_at: Optional[datetime] = Field(None, description="Test completion time")
    duration_seconds: Optional[float] = Field(None, description="Test execution duration")
    
    # Detailed descriptions
    description: str = Field("", description="What this test does and why it matters")
    methodology: str = Field("", description="How the test is performed")
    
    # Specification reference
    spec_reference: Dict[str, str] = Field(
        default_factory=dict,
        description="Specification reference details"
    )
    
    # Expected vs Actual behavior
    expected_behavior: str = Field("", description="Expected behavior according to spec")
    actual_behavior: str = Field("", description="Actual observed behavior")
    
    # Failure details (populated when test fails)
    failure_reason: Optional[str] = Field(None, description="Detailed reason for failure")
    impact_assessment: Optional[ImpactAssessment] = Field(
        None, 
        description="Assessment of failure impact"
    )
    
    # Remediation guidance
    remediation: Optional[Remediation] = Field(
        None,
        description="Steps to fix the issue"
    )
    
    # Evidence and metrics
    evidence: Optional[Evidence] = Field(None, description="Evidence collected during test")
    metrics: Optional[PerformanceMetrics] = Field(None, description="Performance metrics")
    
    # Additional context
    tags: List[str] = Field(default_factory=list, description="Test tags")
    notes: Optional[str] = Field(None, description="Additional notes or context")
    
    # Test dependencies
    depends_on: List[str] = Field(default_factory=list, description="Test dependencies")
    blocked_by: Optional[str] = Field(None, description="Test that blocked execution")
    
    def is_success(self) -> bool:
        """Check if test passed."""
        return self.status == TestStatus.PASSED
    
    def is_failure(self) -> bool:
        """Check if test failed."""
        return self.status in [TestStatus.FAILED, TestStatus.ERROR]
    
    def has_evidence(self) -> bool:
        """Check if test has evidence."""
        return self.evidence is not None and (
            self.evidence.request_sent is not None or 
            self.evidence.response_received is not None
        )
    
    def to_summary(self) -> str:
        """Generate a brief summary of the test result."""
        icon = {
            TestStatus.PASSED: "✅",
            TestStatus.FAILED: "❌",
            TestStatus.WARNING: "⚠️",
            TestStatus.SKIPPED: "⏭️",
            TestStatus.ERROR: "💥",
            TestStatus.PENDING: "⏳",
            TestStatus.RUNNING: "🔄"
        }.get(self.status, "❓")
        
        return f"{icon} [{self.test_id}] {self.test_name}: {self.status}"
    
    def to_verbose_yaml(self) -> Dict[str, Any]:
        """Convert to verbose YAML-friendly dictionary."""
        result = {
            'test_id': self.test_id,
            'test_name': self.test_name,
            'status': self.status.value,
            'severity': self.severity,
            'category': self.category
        }
        
        # Add description fields
        if self.description:
            result['description'] = self.description
        if self.methodology:
            result['test_methodology'] = self.methodology
        
        # Add specification reference
        if self.spec_reference:
            result['specification_reference'] = self.spec_reference
        
        # Add expected vs actual
        if self.expected_behavior:
            result['expected_behavior'] = self.expected_behavior
        if self.actual_behavior:
            result['actual_behavior'] = self.actual_behavior
        
        # Add failure details if failed
        if self.status in [TestStatus.FAILED, TestStatus.ERROR]:
            if self.failure_reason:
                result['failure_reason'] = self.failure_reason
            if self.impact_assessment:
                result['impact_assessment'] = self.impact_assessment.model_dump()
            if self.remediation:
                result['remediation'] = self.remediation.model_dump()
        
        # Add evidence if available
        if self.evidence:
            result['evidence'] = self.evidence.model_dump(exclude_none=True)
        
        # Add metrics if available
        if self.metrics:
            result['performance_metrics'] = self.metrics.model_dump(exclude_none=True)
        
        # Add timing information
        if self.duration_seconds:
            result['duration_seconds'] = round(self.duration_seconds, 3)
        
        return result


class TestSuite(BaseModel):
    """Collection of test results for a complete test run."""
    
    # Metadata
    suite_id: str = Field(description="Unique identifier for this test suite run")
    endpoint: str = Field(description="MCP endpoint being tested")
    started_at: datetime = Field(description="Suite execution start time")
    completed_at: Optional[datetime] = Field(None, description="Suite completion time")
    
    # Results
    results: List[TestResult] = Field(default_factory=list, description="All test results")
    
    # Statistics
    total_tests: int = Field(0, description="Total number of tests")
    passed: int = Field(0, description="Number of passed tests")
    failed: int = Field(0, description="Number of failed tests")
    warnings: int = Field(0, description="Number of warnings")
    skipped: int = Field(0, description="Number of skipped tests")
    errors: int = Field(0, description="Number of test errors")
    
    # Compliance score
    compliance_score: float = Field(0.0, description="Overall compliance percentage")
    
    def add_result(self, result: TestResult):
        """Add a test result and update statistics."""
        self.results.append(result)
        self.total_tests += 1
        
        if result.status == TestStatus.PASSED:
            self.passed += 1
        elif result.status == TestStatus.FAILED:
            self.failed += 1
        elif result.status == TestStatus.WARNING:
            self.warnings += 1
        elif result.status == TestStatus.SKIPPED:
            self.skipped += 1
        elif result.status == TestStatus.ERROR:
            self.errors += 1
        
        # Update compliance score
        if self.total_tests > 0:
            self.compliance_score = (self.passed / self.total_tests) * 100
    
    def get_critical_failures(self) -> List[TestResult]:
        """Get all critical failures."""
        return [
            r for r in self.results
            if r.status == TestStatus.FAILED and r.severity == "CRITICAL"
        ]
    
    def get_by_category(self, category: str) -> List[TestResult]:
        """Get results for a specific category."""
        return [r for r in self.results if r.category == category]
    
    def to_summary(self) -> str:
        """Generate a summary of the test suite."""
        duration = 0.0
        if self.completed_at and self.started_at:
            duration = (self.completed_at - self.started_at).total_seconds()
        
        return f"""
Test Suite Summary
==================
Endpoint: {self.endpoint}
Duration: {duration:.2f} seconds
Total Tests: {self.total_tests}
Passed: {self.passed} ({self.passed/max(1,self.total_tests)*100:.1f}%)
Failed: {self.failed} ({self.failed/max(1,self.total_tests)*100:.1f}%)
Warnings: {self.warnings}
Skipped: {self.skipped}
Errors: {self.errors}
Compliance Score: {self.compliance_score:.1f}%
"""