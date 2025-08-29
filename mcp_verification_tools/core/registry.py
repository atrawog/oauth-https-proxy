"""Test registration and discovery system for modular MCP testing."""

from typing import Dict, List, Callable, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import importlib
import pkgutil
import logging

logger = logging.getLogger(__name__)


class TestCategory(str, Enum):
    """Categories for MCP compliance tests."""
    SESSION = "session_management"
    TRANSPORT = "transport_compliance"
    PROTOCOL = "protocol_compliance"
    TOOLS = "tools_validation"
    SECURITY = "security_compliance"
    PERFORMANCE = "performance_metrics"
    RESOURCES = "resources_validation"
    PROMPTS = "prompts_validation"
    CUSTOM = "custom_tests"


class TestSeverity(str, Enum):
    """Severity levels for test failures."""
    CRITICAL = "CRITICAL"  # Must fix for compliance
    HIGH = "HIGH"          # Should fix soon
    MEDIUM = "MEDIUM"      # Should fix
    LOW = "LOW"            # Nice to have
    INFO = "INFO"          # Informational only


@dataclass
class TestMetadata:
    """Metadata for each registered test."""
    test_id: str
    name: str
    category: TestCategory
    severity: TestSeverity = TestSeverity.MEDIUM
    description: str = ""
    spec_reference: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    timeout: int = 30
    enabled: bool = True


class TestRegistry:
    """Global registry for all MCP compliance tests."""
    _instance: Optional['TestRegistry'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tests = {}
            cls._instance._categories = {}
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_tests'):
            self._tests: Dict[str, Dict[str, Any]] = {}
            self._categories: Dict[TestCategory, List[str]] = {}
    
    def register(self, metadata: TestMetadata) -> Callable:
        """
        Decorator to register a test.
        
        Example:
            @test_registry.register(metadata)
            async def test_function(client: MCPTestBase) -> TestResult:
                pass
        """
        def decorator(func: Callable) -> Callable:
            # Store test with metadata
            self._tests[metadata.test_id] = {
                'function': func,
                'metadata': metadata
            }
            
            # Add to category index
            if metadata.category not in self._categories:
                self._categories[metadata.category] = []
            self._categories[metadata.category].append(metadata.test_id)
            
            # Add function attributes for introspection
            func.test_id = metadata.test_id
            func.test_metadata = metadata
            
            logger.debug(f"Registered test: {metadata.test_id} - {metadata.name}")
            return func
        
        return decorator
    
    def get_test(self, test_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific test by ID."""
        return self._tests.get(test_id)
    
    def get_tests(self, 
                  category: Optional[TestCategory] = None,
                  tags: Optional[List[str]] = None,
                  severity: Optional[TestSeverity] = None,
                  enabled_only: bool = True) -> List[Dict[str, Any]]:
        """
        Get filtered tests.
        
        Args:
            category: Filter by test category
            tags: Filter by tags (tests must have at least one matching tag)
            severity: Filter by minimum severity
            enabled_only: Only return enabled tests
        
        Returns:
            List of test data dictionaries
        """
        tests = []
        
        for test_id, test_data in self._tests.items():
            metadata = test_data['metadata']
            
            # Filter by enabled status
            if enabled_only and not metadata.enabled:
                continue
            
            # Filter by category
            if category and metadata.category != category:
                continue
            
            # Filter by tags (any match)
            if tags and not any(tag in metadata.tags for tag in tags):
                continue
            
            # Filter by severity
            if severity:
                severity_order = [s for s in TestSeverity]
                if severity_order.index(metadata.severity) > severity_order.index(severity):
                    continue
            
            tests.append(test_data)
        
        return tests
    
    def get_categories(self) -> List[TestCategory]:
        """Get all registered test categories."""
        return list(self._categories.keys())
    
    def get_tests_by_category(self, category: TestCategory) -> List[str]:
        """Get all test IDs in a category."""
        return self._categories.get(category, [])
    
    def discover_tests(self, package_path: str = "mcp_verification_tools.tests") -> int:
        """
        Auto-discover and import all test modules.
        
        Args:
            package_path: Dot-separated path to tests package
        
        Returns:
            Number of tests discovered
        """
        initial_count = len(self._tests)
        
        try:
            # Import the base tests package
            tests_module = importlib.import_module(package_path)
            
            # Walk through all submodules
            for importer, modname, ispkg in pkgutil.walk_packages(
                tests_module.__path__,
                prefix=f"{package_path}."
            ):
                try:
                    # Import each module to trigger test registration
                    importlib.import_module(modname)
                    logger.debug(f"Imported test module: {modname}")
                except Exception as e:
                    logger.warning(f"Failed to import {modname}: {e}")
        
        except Exception as e:
            logger.error(f"Failed to discover tests: {e}")
        
        discovered = len(self._tests) - initial_count
        logger.info(f"Discovered {discovered} new tests (total: {len(self._tests)})")
        return discovered
    
    def build_dependency_graph(self, test_ids: List[str]) -> Dict[str, Set[str]]:
        """
        Build dependency graph for test execution order.
        
        Args:
            test_ids: List of test IDs to include
        
        Returns:
            Dictionary mapping test_id to set of dependencies
        """
        graph = {}
        
        for test_id in test_ids:
            test_data = self._tests.get(test_id)
            if test_data:
                deps = test_data['metadata'].depends_on or []
                # Only include dependencies that are in our test list
                graph[test_id] = set(dep for dep in deps if dep in test_ids)
        
        return graph
    
    def get_execution_order(self, test_ids: List[str]) -> List[List[str]]:
        """
        Get test execution order respecting dependencies.
        
        Returns batches of tests that can run in parallel.
        
        Args:
            test_ids: List of test IDs to order
        
        Returns:
            List of batches, where each batch can run in parallel
        """
        graph = self.build_dependency_graph(test_ids)
        completed = set()
        batches = []
        
        while graph:
            # Find tests with satisfied dependencies
            ready = [
                test_id for test_id, deps in graph.items()
                if deps.issubset(completed)
            ]
            
            if not ready:
                # Circular dependency detected
                remaining = list(graph.keys())
                logger.warning(f"Circular dependency detected in tests: {remaining}")
                # Add remaining tests as final batch (may fail)
                batches.append(remaining)
                break
            
            # Add batch of ready tests
            batches.append(ready)
            
            # Mark as completed and remove from graph
            for test_id in ready:
                completed.add(test_id)
                del graph[test_id]
        
        return batches
    
    def clear(self):
        """Clear all registered tests (useful for testing)."""
        self._tests.clear()
        self._categories.clear()
    
    def __len__(self) -> int:
        """Get total number of registered tests."""
        return len(self._tests)
    
    def __repr__(self) -> str:
        """String representation."""
        return f"TestRegistry({len(self._tests)} tests, {len(self._categories)} categories)"


# Global registry instance
test_registry = TestRegistry()


def mcp_test(test_id: str, 
             name: str,
             category: TestCategory,
             severity: TestSeverity = TestSeverity.MEDIUM,
             description: str = "",
             spec_url: str = "",
             spec_section: str = "",
             spec_requirement: str = "",
             tags: Optional[List[str]] = None,
             depends_on: Optional[List[str]] = None,
             timeout: int = 30,
             enabled: bool = True) -> Callable:
    """
    Decorator to register an MCP compliance test.
    
    This is the primary way to create tests - just decorate any async function
    with this decorator and it will be automatically discovered and run.
    
    Args:
        test_id: Unique test identifier (e.g., "SM-001")
        name: Human-readable test name
        category: Test category
        severity: Severity if test fails
        description: Detailed test description
        spec_url: URL to specification reference
        spec_section: Section in specification
        spec_requirement: Specific requirement being tested
        tags: Optional tags for filtering
        depends_on: List of test IDs this depends on
        timeout: Test timeout in seconds
        enabled: Whether test is enabled
    
    Example:
        @mcp_test(
            test_id="SM-001",
            name="Session ID Character Validation",
            category=TestCategory.SESSION,
            severity=TestSeverity.CRITICAL,
            description="Validates session ID character set",
            spec_url="https://modelcontextprotocol.io/...",
            spec_section="Session Management",
            tags=["security", "session"]
        )
        async def test_session_charset(client: MCPClient) -> TestResult:
            # Test implementation
            pass
    """
    metadata = TestMetadata(
        test_id=test_id,
        name=name,
        category=category,
        severity=severity,
        description=description,
        spec_reference={
            'url': spec_url,
            'section': spec_section,
            'requirement': spec_requirement
        },
        tags=tags or [],
        depends_on=depends_on or [],
        timeout=timeout,
        enabled=enabled
    )
    
    return test_registry.register(metadata)