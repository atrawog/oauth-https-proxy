"""Test runner for orchestrating MCP compliance test execution."""

import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Callable
from pathlib import Path

import httpx

from .registry import TestRegistry, TestCategory, TestSeverity, test_registry
from .base_test import MCPTestBase
from ..models.test_results import TestResult, TestStatus, TestSuite
from ..models.config import TestConfig


logger = logging.getLogger(__name__)


class TestRunner:
    """
    Orchestrates test execution with dependency management and parallel execution.
    
    Features:
    - Automatic test discovery
    - Dependency resolution
    - Parallel execution with batching
    - Fail-fast mode
    - Progress tracking
    - Comprehensive error handling
    """
    
    def __init__(self, config: TestConfig):
        """
        Initialize test runner with configuration.
        
        Args:
            config: Test configuration
        """
        self.config = config
        self.endpoint = str(config.endpoint)
        self.test_registry = test_registry
        self.results: List[TestResult] = []
        self.suite = TestSuite(
            suite_id=str(uuid.uuid4()),
            endpoint=self.endpoint,
            started_at=datetime.utcnow()
        )
        self.progress_callback: Optional[Callable] = None
        self._stop_requested = False
    
    async def run_tests(self,
                       category: Optional[TestCategory] = None,
                       tags: Optional[List[str]] = None,
                       test_ids: Optional[List[str]] = None) -> TestSuite:
        """
        Run tests based on filters and configuration.
        
        Args:
            category: Optional category filter
            tags: Optional tag filter
            test_ids: Optional specific test IDs
        
        Returns:
            TestSuite with all results
        """
        logger.info(f"Starting test run for endpoint: {self.endpoint}")
        
        # Discover all available tests
        discovered = self.test_registry.discover_tests()
        logger.info(f"Discovered {discovered} tests")
        
        # Get filtered tests
        tests = self._get_filtered_tests(category, tags, test_ids)
        
        if not tests:
            logger.warning("No tests matched the filters")
            self.suite.completed_at = datetime.utcnow()
            return self.suite
        
        logger.info(f"Running {len(tests)} tests")
        
        # Execute tests
        if self.config.parallel and len(tests) > 1:
            await self._run_parallel(tests)
        else:
            await self._run_sequential(tests)
        
        # Finalize suite
        self.suite.completed_at = datetime.utcnow()
        
        logger.info(
            f"Test run complete: {self.suite.passed}/{self.suite.total_tests} passed "
            f"({self.suite.compliance_score:.1f}% compliance)"
        )
        
        return self.suite
    
    def _get_filtered_tests(self,
                           category: Optional[TestCategory],
                           tags: Optional[List[str]],
                           test_ids: Optional[List[str]]) -> List[Dict[str, Any]]:
        """
        Get tests based on filters.
        
        Args:
            category: Category filter
            tags: Tag filter
            test_ids: Specific test IDs
        
        Returns:
            List of test data dictionaries
        """
        # If specific test IDs provided, use those
        if test_ids:
            tests = []
            for test_id in test_ids:
                test = self.test_registry.get_test(test_id)
                if test:
                    tests.append(test)
                else:
                    logger.warning(f"Test not found: {test_id}")
            return tests
        
        # Otherwise use category/tag filters from config and parameters
        filter_category = category or (
            TestCategory(self.config.categories[0]) 
            if self.config.categories else None
        )
        
        filter_tags = tags or self.config.tags
        
        # Get tests with filters
        tests = self.test_registry.get_tests(
            category=filter_category,
            tags=filter_tags,
            enabled_only=True
        )
        
        # Apply skip list
        if self.config.skip_tests:
            tests = [
                t for t in tests 
                if t['metadata'].test_id not in self.config.skip_tests
            ]
        
        return tests
    
    async def _run_sequential(self, tests: List[Dict[str, Any]]):
        """
        Run tests sequentially.
        
        Args:
            tests: List of tests to run
        """
        for test_data in tests:
            if self._stop_requested:
                logger.info("Stop requested, halting test execution")
                break
            
            result = await self._run_single_test(test_data)
            self._handle_test_result(result)
            
            # Check fail-fast
            if self._should_stop_on_failure(result):
                break
    
    async def _run_parallel(self, tests: List[Dict[str, Any]]):
        """
        Run tests in parallel with dependency resolution.
        
        Args:
            tests: List of tests to run
        """
        # Get execution order (batches that respect dependencies)
        test_ids = [t['metadata'].test_id for t in tests]
        batches = self.test_registry.get_execution_order(test_ids)
        
        # Map test_id back to test data
        test_map = {t['metadata'].test_id: t for t in tests}
        
        # Run batches
        for batch_num, batch_ids in enumerate(batches, 1):
            if self._stop_requested:
                logger.info("Stop requested, halting test execution")
                break
            
            logger.debug(f"Running batch {batch_num}/{len(batches)} with {len(batch_ids)} tests")
            
            # Create tasks for this batch
            tasks = []
            for test_id in batch_ids:
                test_data = test_map.get(test_id)
                if test_data:
                    tasks.append(self._run_single_test(test_data))
            
            # Run batch in parallel
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Handle results
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Test execution error: {result}")
                        # Create error result
                        error_result = TestResult(
                            test_id="ERROR",
                            test_name="Execution Error",
                            category="unknown",
                            status=TestStatus.ERROR,
                            severity="HIGH",
                            failure_reason=str(result)
                        )
                        self._handle_test_result(error_result)
                    else:
                        self._handle_test_result(result)
                        
                        # Check fail-fast after each result
                        if self._should_stop_on_failure(result):
                            self._stop_requested = True
                            break
    
    async def _run_single_test(self, test_data: Dict[str, Any]) -> TestResult:
        """
        Run a single test with timeout and error handling.
        
        Args:
            test_data: Test data from registry
        
        Returns:
            TestResult
        """
        metadata = test_data['metadata']
        test_func = test_data['function']
        
        logger.debug(f"Running test: {metadata.test_id} - {metadata.name}")
        
        # Create test client
        client = MCPTestBase(self.endpoint)
        
        try:
            # Run test with timeout
            result = await asyncio.wait_for(
                test_func(client),
                timeout=metadata.timeout
            )
            
            # Ensure we have a TestResult
            if not isinstance(result, TestResult):
                logger.warning(f"Test {metadata.test_id} did not return TestResult")
                result = TestResult(
                    test_id=metadata.test_id,
                    test_name=metadata.name,
                    category=metadata.category.value,
                    status=TestStatus.ERROR,
                    severity=metadata.severity.value,
                    failure_reason="Test did not return proper TestResult"
                )
            
            # Enhance result with metadata if missing
            if not result.test_name:
                result.test_name = metadata.name
            if not result.category:
                result.category = metadata.category.value
            if not result.severity:
                result.severity = metadata.severity.value
            if not result.description:
                result.description = metadata.description
            if not result.spec_reference:
                result.spec_reference = metadata.spec_reference
            
            # Set completion time
            result.completed_at = datetime.utcnow()
            if result.started_at:
                result.duration_seconds = (
                    result.completed_at - result.started_at
                ).total_seconds()
            
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"Test {metadata.test_id} timed out after {metadata.timeout}s")
            return TestResult(
                test_id=metadata.test_id,
                test_name=metadata.name,
                category=metadata.category.value,
                status=TestStatus.ERROR,
                severity=metadata.severity.value,
                failure_reason=f"Test timed out after {metadata.timeout} seconds",
                completed_at=datetime.utcnow()
            )
            
        except Exception as e:
            logger.error(f"Test {metadata.test_id} failed with exception: {e}")
            return TestResult(
                test_id=metadata.test_id,
                test_name=metadata.name,
                category=metadata.category.value,
                status=TestStatus.ERROR,
                severity=metadata.severity.value,
                failure_reason=f"Test failed with exception: {str(e)}",
                completed_at=datetime.utcnow()
            )
            
        finally:
            # Clean up client
            try:
                await client.cleanup()
            except Exception as e:
                logger.debug(f"Client cleanup error: {e}")
    
    def _handle_test_result(self, result: TestResult):
        """
        Handle a test result - add to suite and trigger callbacks.
        
        Args:
            result: Test result to handle
        """
        # Add to suite
        self.suite.add_result(result)
        
        # Log result
        if result.status == TestStatus.PASSED:
            logger.info(f"✅ {result.test_id}: {result.test_name}")
        elif result.status == TestStatus.FAILED:
            logger.warning(f"❌ {result.test_id}: {result.test_name}")
            if result.failure_reason and self.config.verbose:
                logger.warning(f"   Reason: {result.failure_reason}")
        elif result.status == TestStatus.WARNING:
            logger.warning(f"⚠️ {result.test_id}: {result.test_name}")
        elif result.status == TestStatus.SKIPPED:
            logger.info(f"⏭️ {result.test_id}: {result.test_name}")
        else:
            logger.error(f"💥 {result.test_id}: {result.test_name}")
        
        # Trigger progress callback if set
        if self.progress_callback:
            try:
                self.progress_callback(result, self.suite)
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")
    
    def _should_stop_on_failure(self, result: TestResult) -> bool:
        """
        Check if we should stop execution based on result.
        
        Args:
            result: Test result to check
        
        Returns:
            True if should stop
        """
        if not self.config.fail_fast:
            return False
        
        # Stop on critical failures
        if (result.status == TestStatus.FAILED and 
            result.severity == TestSeverity.CRITICAL.value):
            logger.info(f"Critical failure in {result.test_id}, stopping execution")
            return True
        
        # Stop on any failure in strict mode
        if self.config.strict and result.status == TestStatus.FAILED:
            logger.info(f"Failure in strict mode, stopping execution")
            return True
        
        return False
    
    def set_progress_callback(self, callback: Callable[[TestResult, TestSuite], None]):
        """
        Set a callback to be triggered after each test.
        
        Args:
            callback: Function to call with (result, suite)
        """
        self.progress_callback = callback
    
    def stop(self):
        """Request test execution to stop."""
        self._stop_requested = True
        logger.info("Stop requested for test runner")


class StressTestRunner(TestRunner):
    """
    Extended runner for stress testing MCP endpoints.
    """
    
    async def run_stress_test(self, 
                             duration_seconds: int = 60,
                             concurrent_sessions: int = 50) -> Dict[str, Any]:
        """
        Run stress tests on the endpoint.
        
        Args:
            duration_seconds: How long to run the test
            concurrent_sessions: Number of concurrent sessions
        
        Returns:
            Stress test metrics
        """
        logger.info(
            f"Starting stress test: {concurrent_sessions} sessions "
            f"for {duration_seconds} seconds"
        )
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_sessions': 0,
            'active_sessions': 0,
            'response_times': [],
            'errors': []
        }
        
        # Create session tasks
        tasks = []
        for i in range(concurrent_sessions):
            tasks.append(
                self._stress_session(i, end_time, metrics)
            )
        
        # Run all sessions
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Calculate statistics
        elapsed = time.time() - start_time
        metrics['duration_seconds'] = elapsed
        metrics['requests_per_second'] = metrics['total_requests'] / elapsed
        
        if metrics['response_times']:
            metrics['avg_response_time_ms'] = sum(metrics['response_times']) / len(metrics['response_times'])
            metrics['min_response_time_ms'] = min(metrics['response_times'])
            metrics['max_response_time_ms'] = max(metrics['response_times'])
        
        logger.info(f"Stress test complete: {metrics['total_requests']} requests")
        
        return metrics
    
    async def _stress_session(self, 
                             session_num: int,
                             end_time: float,
                             metrics: Dict[str, Any]):
        """
        Run a single stress test session.
        
        Args:
            session_num: Session number
            end_time: When to stop
            metrics: Shared metrics dictionary
        """
        client = MCPTestBase(self.endpoint)
        metrics['total_sessions'] += 1
        metrics['active_sessions'] += 1
        
        try:
            # Initialize session
            await client.initialize_session()
            
            # Keep making requests until time is up
            while time.time() < end_time:
                start = time.perf_counter()
                
                try:
                    # Send a simple ping request
                    response = await client.send_request({
                        "jsonrpc": "2.0",
                        "id": metrics['total_requests'] + 1,
                        "method": "ping"
                    })
                    
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    metrics['response_times'].append(elapsed_ms)
                    metrics['successful_requests'] += 1
                    
                except Exception as e:
                    metrics['failed_requests'] += 1
                    metrics['errors'].append(str(e))
                
                metrics['total_requests'] += 1
                
                # Small delay between requests
                await asyncio.sleep(0.1)
                
        except Exception as e:
            logger.debug(f"Session {session_num} error: {e}")
        
        finally:
            metrics['active_sessions'] -= 1
            await client.cleanup()