#!/usr/bin/env python3
"""
MCP Session Management & Performance Stress Test Suite
=======================================================
Comprehensive testing tool for MCP with focus on:
- Session management compliance (per MCP specification)
- Tool performance measurement
- Concurrent session isolation
- SSE stream stability under load

MCP Specification Compliance:
- Session IDs: Visible ASCII only (0x21-0x7E)
- Session lifecycle: initialize → use → terminate
- Error codes: 400 (missing), 404 (invalid), 405 (not allowed)
"""

import asyncio
import httpx
import json
import time
import argparse
import statistics
import sys
import traceback
import random
import string
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict


class TestMode(Enum):
    QUICK = "quick"
    SESSIONS = "sessions"
    TOOLS = "tools"
    STRESS = "stress"
    ENDURANCE = "endurance"
    ALL = "all"


@dataclass
class SessionTestResult:
    """Session-specific test result."""
    test_name: str
    passed: bool
    message: str
    session_id: Optional[str] = None
    duration_ms: float = 0
    details: Optional[Dict] = None


@dataclass
class ToolPerformanceMetrics:
    """Tool execution performance metrics."""
    tool_name: str
    execution_count: int
    success_count: int
    failure_count: int
    min_ms: float
    max_ms: float
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    error_rate: float
    payload_size_bytes: Optional[int] = None


@dataclass
class SessionMetrics:
    """Session management metrics."""
    session_id: str
    created_at: datetime
    last_used: datetime
    request_count: int
    error_count: int
    duration_seconds: float
    terminated_properly: bool = False
    tools_executed: List[str] = field(default_factory=list)


class MCPSessionStressTest:
    """Enhanced MCP stress test with session management focus."""
    
    def __init__(self, base_url: str, verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.mcp_url = self.base_url  # URL already includes /mcp
        self.verbose = verbose
        
        # Results storage
        self.session_results: List[SessionTestResult] = []
        self.tool_metrics: Dict[str, ToolPerformanceMetrics] = {}
        self.session_metrics: Dict[str, SessionMetrics] = {}
        
        # Performance tracking
        self.tool_execution_times: Dict[str, List[float]] = defaultdict(list)
        self.session_creation_times: List[float] = []
        self.session_termination_times: List[float] = []
        
    def log(self, message: str, level: str = "INFO"):
        """Log message with timestamp."""
        if self.verbose or level in ["ERROR", "WARNING", "SUCCESS"]:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            prefix = {
                "ERROR": "❌",
                "WARNING": "⚠️",
                "INFO": "ℹ️",
                "SUCCESS": "✅",
                "DEBUG": "🔍",
                "SESSION": "🔐",
                "TOOL": "🔧"
            }.get(level, "•")
            print(f"[{timestamp}] {prefix} {message}")
    
    # ========== SESSION MANAGEMENT TESTS ==========
    
    async def test_session_id_format(self) -> SessionTestResult:
        """Test 1: Verify session ID format compliance with MCP spec."""
        self.log("Testing session ID format compliance...", "SESSION")
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                # Initialize session
                response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"},
                        "jsonrpc": "2.0",
                        "id": 0
                    }
                )
                
                if response.status_code != 200:
                    return SessionTestResult(
                        "Session ID Format",
                        False,
                        f"Initialization failed: {response.status_code}"
                    )
                
                session_id = response.headers.get("mcp-session-id")
                if not session_id:
                    return SessionTestResult(
                        "Session ID Format",
                        False,
                        "No session ID in response headers"
                    )
                
                # Validate format: visible ASCII only (0x21-0x7E)
                valid_ascii = all(0x21 <= ord(c) <= 0x7E for c in session_id)
                
                # Check for reasonable length (UUID-like)
                reasonable_length = 8 <= len(session_id) <= 128
                
                # Check for cryptographic appearance (mix of chars)
                has_variety = (
                    any(c.isdigit() for c in session_id) and
                    any(c.isalpha() for c in session_id)
                )
                
                details = {
                    "session_id": session_id,
                    "length": len(session_id),
                    "valid_ascii": valid_ascii,
                    "reasonable_length": reasonable_length,
                    "has_variety": has_variety
                }
                
                all_checks = valid_ascii and reasonable_length
                
                return SessionTestResult(
                    "Session ID Format",
                    all_checks,
                    f"Session ID {'valid' if all_checks else 'invalid'}",
                    session_id=session_id,
                    details=details
                )
                
        except Exception as e:
            return SessionTestResult(
                "Session ID Format",
                False,
                f"Error: {e}"
            )
    
    async def test_session_lifecycle(self) -> SessionTestResult:
        """Test 2: Complete session lifecycle (create, use, terminate)."""
        self.log("Testing session lifecycle...", "SESSION")
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                start = time.perf_counter()
                
                # 1. Create session
                init_response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"},
                        "jsonrpc": "2.0",
                        "id": 0
                    }
                )
                
                session_id = init_response.headers.get("mcp-session-id")
                if not session_id:
                    return SessionTestResult(
                        "Session Lifecycle",
                        False,
                        "No session ID created"
                    )
                
                self.log(f"Session created: {session_id}", "DEBUG")
                
                # 2. Use session for multiple requests
                successful_uses = 0
                for i in range(3):
                    response = await client.post(
                        self.mcp_url,
                        json={
                            "method": "tools/list",
                            "params": {},
                            "jsonrpc": "2.0",
                            "id": i + 1
                        },
                        headers={"Mcp-Session-Id": session_id}
                    )
                    
                    if response.status_code == 200:
                        successful_uses += 1
                
                # 3. Terminate session
                delete_response = await client.delete(
                    self.mcp_url,
                    headers={"Mcp-Session-Id": session_id}
                )
                
                terminated_properly = delete_response.status_code in [204, 200]
                self.log(f"DELETE response: {delete_response.status_code}", "DEBUG")
                
                # 4. Verify session is terminated (should get 404)
                post_delete_response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "tools/list",
                        "params": {},
                        "jsonrpc": "2.0",
                        "id": 99
                    },
                    headers={"Mcp-Session-Id": session_id}
                )
                
                session_terminated = post_delete_response.status_code == 404
                
                duration_ms = (time.perf_counter() - start) * 1000
                
                # All checks must pass
                all_passed = (
                    successful_uses == 3 and
                    terminated_properly and
                    session_terminated
                )
                
                return SessionTestResult(
                    "Session Lifecycle",
                    all_passed,
                    f"Lifecycle {'complete' if all_passed else 'incomplete'}",
                    session_id=session_id,
                    duration_ms=duration_ms,
                    details={
                        "successful_uses": successful_uses,
                        "terminated_properly": terminated_properly,
                        "session_invalidated": session_terminated
                    }
                )
                
        except Exception as e:
            return SessionTestResult(
                "Session Lifecycle",
                False,
                f"Error: {e}"
            )
    
    async def test_session_isolation(self, num_sessions: int = 5) -> SessionTestResult:
        """Test 3: Concurrent sessions don't interfere with each other."""
        self.log(f"Testing {num_sessions} concurrent session isolation...", "SESSION")
        
        async def create_and_use_session(session_num: int) -> Tuple[bool, str, Dict]:
            """Create a session and execute operations."""
            try:
                async with httpx.AsyncClient(verify=False, timeout=30) as client:
                    # Create session
                    init_response = await client.post(
                        self.mcp_url,
                        json={
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2025-06-18",
                                "clientInfo": {"name": f"TestClient-{session_num}"}
                            },
                            "jsonrpc": "2.0",
                            "id": 0
                        }
                    )
                    
                    session_id = init_response.headers.get("mcp-session-id")
                    if not session_id:
                        return False, f"Session {session_num}: No ID", {}
                    
                    # Execute unique operations
                    operations_successful = True
                    for op in range(3):
                        response = await client.post(
                            self.mcp_url,
                            json={
                                "method": "tools/list",
                                "params": {},
                                "jsonrpc": "2.0",
                                "id": op + 1
                            },
                            headers={"Mcp-Session-Id": session_id}
                        )
                        
                        if response.status_code != 200:
                            operations_successful = False
                            break
                    
                    return operations_successful, session_id, {
                        "session_num": session_num,
                        "operations": 3,
                        "success": operations_successful
                    }
                    
            except Exception as e:
                return False, f"Session {session_num}: {e}", {}
        
        try:
            # Launch concurrent sessions
            start = time.perf_counter()
            tasks = [create_and_use_session(i) for i in range(num_sessions)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            duration_ms = (time.perf_counter() - start) * 1000
            
            # Analyze results
            successful_sessions = []
            failed_sessions = []
            session_ids = set()
            
            for result in results:
                if isinstance(result, tuple):
                    success, session_id, details = result
                    if success:
                        successful_sessions.append(session_id)
                        session_ids.add(session_id)
                    else:
                        failed_sessions.append(session_id)
            
            # Check for unique session IDs (no duplicates)
            unique_sessions = len(session_ids) == len(successful_sessions)
            isolation_maintained = len(successful_sessions) >= num_sessions * 0.8
            
            return SessionTestResult(
                "Session Isolation",
                unique_sessions and isolation_maintained,
                f"{len(successful_sessions)}/{num_sessions} isolated sessions",
                duration_ms=duration_ms,
                details={
                    "total_sessions": num_sessions,
                    "successful": len(successful_sessions),
                    "failed": len(failed_sessions),
                    "unique_ids": unique_sessions,
                    "session_ids": list(session_ids)[:5]  # First 5 for reference
                }
            )
            
        except Exception as e:
            return SessionTestResult(
                "Session Isolation",
                False,
                f"Error: {e}"
            )
    
    async def test_session_error_handling(self) -> SessionTestResult:
        """Test 4: Session error handling per MCP spec."""
        self.log("Testing session error handling...", "SESSION")
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                errors_handled_correctly = []
                
                # Test 1: Missing session ID (should get 400 or work without session)
                response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "tools/list",
                        "params": {},
                        "jsonrpc": "2.0",
                        "id": 1
                    }
                    # No session header
                )
                
                # Some servers may allow sessionless requests
                missing_session_ok = response.status_code in [200, 400]
                errors_handled_correctly.append(("missing_session", missing_session_ok))
                
                # Test 2: Invalid session ID (should get 404)
                invalid_id = "INVALID_" + "".join(random.choices(string.ascii_letters, k=20))
                response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "tools/list",
                        "params": {},
                        "jsonrpc": "2.0",
                        "id": 2
                    },
                    headers={"Mcp-Session-Id": invalid_id}
                )
                
                invalid_session_ok = response.status_code in [404, 400]
                errors_handled_correctly.append(("invalid_session", invalid_session_ok))
                
                # Test 3: Session with invalid format (should get 404 as non-existent)
                # Spaces (0x20) are below the valid range (0x21-0x7E)
                bad_chars_id = "test session with spaces"  # Invalid: contains spaces
                response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "tools/list",
                        "params": {},
                        "jsonrpc": "2.0",
                        "id": 3
                    },
                    headers={"Mcp-Session-Id": bad_chars_id}
                )
                
                # Should get 404 (session not found) or 400 (bad format)
                bad_chars_ok = response.status_code in [400, 404]
                errors_handled_correctly.append(("bad_characters", bad_chars_ok))
                
                # All error cases handled correctly?
                all_correct = all(result for _, result in errors_handled_correctly)
                
                return SessionTestResult(
                    "Session Error Handling",
                    all_correct,
                    f"{sum(1 for _, r in errors_handled_correctly if r)}/3 errors handled correctly",
                    details={
                        test: "✅" if result else "❌"
                        for test, result in errors_handled_correctly
                    }
                )
                
        except Exception as e:
            return SessionTestResult(
                "Session Error Handling",
                False,
                f"Error: {e}"
            )
    
    # ========== TOOL PERFORMANCE TESTS ==========
    
    async def test_tool_discovery_performance(self, iterations: int = 10) -> SessionTestResult:
        """Test 5: Tool discovery performance measurement."""
        self.log(f"Testing tool discovery performance ({iterations} iterations)...", "TOOL")
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=30) as client:
                # Create session
                init_response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"},
                        "jsonrpc": "2.0",
                        "id": 0
                    }
                )
                
                session_id = init_response.headers.get("mcp-session-id", "default")
                
                # Measure tool discovery times
                discovery_times = []
                tool_counts = []
                
                for i in range(iterations):
                    start = time.perf_counter()
                    
                    response = await client.post(
                        self.mcp_url,
                        json={
                            "method": "tools/list",
                            "params": {},
                            "jsonrpc": "2.0",
                            "id": i + 1
                        },
                        headers={"Mcp-Session-Id": session_id}
                    )
                    
                    duration_ms = (time.perf_counter() - start) * 1000
                    discovery_times.append(duration_ms)
                    
                    if response.status_code == 200:
                        data = response.json()
                        tools = data.get("result", {}).get("tools", [])
                        tool_counts.append(len(tools))
                    
                    # Small delay between iterations
                    if i < iterations - 1:
                        await asyncio.sleep(0.1)
                
                # Calculate metrics
                if discovery_times:
                    metrics = {
                        "iterations": iterations,
                        "min_ms": min(discovery_times),
                        "max_ms": max(discovery_times),
                        "mean_ms": statistics.mean(discovery_times),
                        "median_ms": statistics.median(discovery_times),
                        "p95_ms": statistics.quantiles(discovery_times, n=20)[18] if len(discovery_times) > 1 else discovery_times[0],
                        "tool_count": tool_counts[0] if tool_counts else 0,
                        "consistent_count": len(set(tool_counts)) == 1 if tool_counts else False
                    }
                    
                    # Performance targets
                    meets_targets = (
                        metrics["p95_ms"] < 100 and  # Under 100ms p95
                        metrics["consistent_count"]   # Same tools every time
                    )
                    
                    return SessionTestResult(
                        "Tool Discovery Performance",
                        meets_targets,
                        f"P95: {metrics['p95_ms']:.1f}ms, Tools: {metrics['tool_count']}",
                        session_id=session_id,
                        duration_ms=sum(discovery_times),
                        details=metrics
                    )
                else:
                    return SessionTestResult(
                        "Tool Discovery Performance",
                        False,
                        "No measurements collected"
                    )
                    
        except Exception as e:
            return SessionTestResult(
                "Tool Discovery Performance",
                False,
                f"Error: {e}"
            )
    
    async def test_tool_execution_performance(self) -> SessionTestResult:
        """Test 6: Individual tool execution performance."""
        self.log("Testing tool execution performance...", "TOOL")
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=30) as client:
                # Create session
                init_response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"},
                        "jsonrpc": "2.0",
                        "id": 0
                    }
                )
                
                session_id = init_response.headers.get("mcp-session-id", "default")
                
                # Get available tools
                tools_response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "tools/list",
                        "params": {},
                        "jsonrpc": "2.0",
                        "id": 1
                    },
                    headers={"Mcp-Session-Id": session_id}
                )
                
                if tools_response.status_code != 200:
                    return SessionTestResult(
                        "Tool Execution Performance",
                        False,
                        "Failed to list tools"
                    )
                
                tools_data = tools_response.json()
                tools = tools_data.get("result", {}).get("tools", [])
                
                # Test first 5 tools or specific test tools
                test_tools = ["echo", "health_check", "proxy_list", "system_info"]
                tools_to_test = [t for t in tools if t["name"] in test_tools][:5]
                
                tool_metrics = {}
                
                for tool in tools_to_test:
                    tool_name = tool["name"]
                    execution_times = []
                    successes = 0
                    failures = 0
                    
                    # Prepare tool arguments
                    args = {}
                    if tool_name == "echo":
                        args = {"message": "test"}
                    
                    # Execute tool multiple times
                    for i in range(5):
                        start = time.perf_counter()
                        
                        response = await client.post(
                            self.mcp_url,
                            json={
                                "method": "tools/call",
                                "params": {
                                    "name": tool_name,
                                    "arguments": args
                                },
                                "jsonrpc": "2.0",
                                "id": 100 + i
                            },
                            headers={"Mcp-Session-Id": session_id}
                        )
                        
                        duration_ms = (time.perf_counter() - start) * 1000
                        execution_times.append(duration_ms)
                        
                        if response.status_code == 200:
                            successes += 1
                        else:
                            failures += 1
                        
                        await asyncio.sleep(0.05)  # Small delay
                    
                    # Calculate tool metrics
                    if execution_times:
                        tool_metrics[tool_name] = {
                            "executions": len(execution_times),
                            "successes": successes,
                            "failures": failures,
                            "min_ms": min(execution_times),
                            "mean_ms": statistics.mean(execution_times),
                            "max_ms": max(execution_times),
                            "success_rate": (successes / len(execution_times)) * 100
                        }
                
                # Overall assessment
                if tool_metrics:
                    avg_success_rate = statistics.mean(
                        m["success_rate"] for m in tool_metrics.values()
                    )
                    avg_mean_time = statistics.mean(
                        m["mean_ms"] for m in tool_metrics.values()
                    )
                    
                    meets_targets = (
                        avg_success_rate >= 90 and  # 90% success rate
                        avg_mean_time < 500          # Under 500ms average
                    )
                    
                    return SessionTestResult(
                        "Tool Execution Performance",
                        meets_targets,
                        f"Tested {len(tool_metrics)} tools, Avg time: {avg_mean_time:.1f}ms",
                        session_id=session_id,
                        details=tool_metrics
                    )
                else:
                    return SessionTestResult(
                        "Tool Execution Performance",
                        False,
                        "No tools tested"
                    )
                    
        except Exception as e:
            return SessionTestResult(
                "Tool Execution Performance",
                False,
                f"Error: {e}"
            )
    
    # ========== SESSION STRESS TESTS ==========
    
    async def test_concurrent_sessions_stress(self, num_sessions: int = 20, requests_per_session: int = 10) -> SessionTestResult:
        """Test 7: Stress test with many concurrent sessions."""
        self.log(f"Stress testing {num_sessions} concurrent sessions...", "SESSION")
        
        async def session_worker(worker_id: int) -> Dict:
            """Worker that creates session and executes requests."""
            metrics = {
                "worker_id": worker_id,
                "session_id": None,
                "requests_completed": 0,
                "errors": 0,
                "total_time_ms": 0
            }
            
            try:
                async with httpx.AsyncClient(verify=False, timeout=60) as client:
                    start = time.perf_counter()
                    
                    # Create session
                    init_response = await client.post(
                        self.mcp_url,
                        json={
                            "method": "initialize",
                            "params": {"protocolVersion": "2025-06-18"},
                            "jsonrpc": "2.0",
                            "id": 0
                        }
                    )
                    
                    session_id = init_response.headers.get("mcp-session-id")
                    if not session_id:
                        metrics["errors"] += 1
                        return metrics
                    
                    metrics["session_id"] = session_id
                    
                    # Execute requests
                    for req_num in range(requests_per_session):
                        try:
                            # Alternate between different methods
                            if req_num % 3 == 0:
                                method = "tools/list"
                                params = {}
                            else:
                                method = "tools/call"
                                params = {
                                    "name": "echo",
                                    "arguments": {"message": f"test-{worker_id}-{req_num}"}
                                }
                            
                            response = await client.post(
                                self.mcp_url,
                                json={
                                    "method": method,
                                    "params": params,
                                    "jsonrpc": "2.0",
                                    "id": req_num + 1
                                },
                                headers={"Mcp-Session-Id": session_id}
                            )
                            
                            if response.status_code == 200:
                                metrics["requests_completed"] += 1
                            else:
                                metrics["errors"] += 1
                            
                        except Exception:
                            metrics["errors"] += 1
                        
                        # Small random delay
                        await asyncio.sleep(random.uniform(0.01, 0.05))
                    
                    # Terminate session
                    try:
                        await client.delete(
                            self.mcp_url,
                            headers={"Mcp-Session-Id": session_id}
                        )
                    except:
                        pass
                    
                    metrics["total_time_ms"] = (time.perf_counter() - start) * 1000
                    
            except Exception as e:
                metrics["errors"] += 1
                self.log(f"Worker {worker_id} error: {e}", "DEBUG")
            
            return metrics
        
        try:
            # Launch all workers
            start = time.perf_counter()
            tasks = [session_worker(i) for i in range(num_sessions)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            total_duration_ms = (time.perf_counter() - start) * 1000
            
            # Analyze results
            successful_sessions = 0
            total_requests = 0
            total_errors = 0
            unique_sessions = set()
            
            for result in results:
                if isinstance(result, dict):
                    if result["session_id"]:
                        successful_sessions += 1
                        unique_sessions.add(result["session_id"])
                    total_requests += result["requests_completed"]
                    total_errors += result["errors"]
            
            # Calculate metrics
            expected_requests = num_sessions * requests_per_session
            request_success_rate = (total_requests / expected_requests * 100) if expected_requests > 0 else 0
            session_success_rate = (successful_sessions / num_sessions * 100)
            
            # Success criteria
            meets_targets = (
                session_success_rate >= 80 and  # 80% sessions successful
                request_success_rate >= 70 and  # 70% requests successful
                len(unique_sessions) == successful_sessions  # All unique IDs
            )
            
            return SessionTestResult(
                "Concurrent Sessions Stress",
                meets_targets,
                f"{successful_sessions}/{num_sessions} sessions, {total_requests}/{expected_requests} requests",
                duration_ms=total_duration_ms,
                details={
                    "sessions_attempted": num_sessions,
                    "sessions_successful": successful_sessions,
                    "requests_per_session": requests_per_session,
                    "total_requests": total_requests,
                    "total_errors": total_errors,
                    "unique_sessions": len(unique_sessions),
                    "session_success_rate": session_success_rate,
                    "request_success_rate": request_success_rate
                }
            )
            
        except Exception as e:
            return SessionTestResult(
                "Concurrent Sessions Stress",
                False,
                f"Error: {e}"
            )
    
    async def test_session_recovery(self) -> SessionTestResult:
        """Test 8: Session recovery after errors."""
        self.log("Testing session recovery after errors...", "SESSION")
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=30) as client:
                recovery_scenarios = []
                
                # Scenario 1: Recovery after 404 (invalid session)
                self.log("Testing recovery after 404...", "DEBUG")
                
                # Try with invalid session
                response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "tools/list",
                        "params": {},
                        "jsonrpc": "2.0",
                        "id": 1
                    },
                    headers={"Mcp-Session-Id": "INVALID_SESSION"}
                )
                
                got_404 = response.status_code == 404
                
                # Now reinitialize
                init_response = await client.post(
                    self.mcp_url,
                    json={
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"},
                        "jsonrpc": "2.0",
                        "id": 2
                    }
                )
                
                new_session_id = init_response.headers.get("mcp-session-id")
                recovered = new_session_id is not None
                
                recovery_scenarios.append({
                    "scenario": "404_recovery",
                    "got_error": got_404,
                    "recovered": recovered
                })
                
                # Scenario 2: Session continuity after transient error
                self.log("Testing session continuity...", "DEBUG")
                
                if new_session_id:
                    # Cause an error (bad request)
                    bad_response = await client.post(
                        self.mcp_url,
                        json={
                            "method": "invalid_method",
                            "params": {},
                            "jsonrpc": "2.0",
                            "id": 3
                        },
                        headers={"Mcp-Session-Id": new_session_id}
                    )
                    
                    # Try using session again
                    good_response = await client.post(
                        self.mcp_url,
                        json={
                            "method": "tools/list",
                            "params": {},
                            "jsonrpc": "2.0",
                            "id": 4
                        },
                        headers={"Mcp-Session-Id": new_session_id}
                    )
                    
                    session_survived = good_response.status_code == 200
                    
                    recovery_scenarios.append({
                        "scenario": "error_continuity",
                        "session_survived": session_survived
                    })
                
                # All scenarios successful?
                all_recovered = all(
                    s.get("recovered", True) and s.get("session_survived", True)
                    for s in recovery_scenarios
                )
                
                return SessionTestResult(
                    "Session Recovery",
                    all_recovered,
                    f"Recovered from {len(recovery_scenarios)} scenarios",
                    details=recovery_scenarios
                )
                
        except Exception as e:
            return SessionTestResult(
                "Session Recovery",
                False,
                f"Error: {e}"
            )
    
    # ========== TEST EXECUTION ==========
    
    async def run_session_tests(self) -> List[SessionTestResult]:
        """Run all session management tests."""
        tests = [
            self.test_session_id_format(),
            self.test_session_lifecycle(),
            self.test_session_isolation(5),
            self.test_session_error_handling(),
            self.test_session_recovery(),
        ]
        
        results = []
        for test in tests:
            result = await test
            results.append(result)
            self.log(f"{'✅' if result.passed else '❌'} {result.test_name}: {result.message}", "SUCCESS" if result.passed else "ERROR")
            await asyncio.sleep(0.5)  # Brief pause
        
        return results
    
    async def run_tool_tests(self, iterations: int = 10) -> List[SessionTestResult]:
        """Run tool performance tests."""
        tests = [
            self.test_tool_discovery_performance(iterations),
            self.test_tool_execution_performance(),
        ]
        
        results = []
        for test in tests:
            result = await test
            results.append(result)
            self.log(f"{'✅' if result.passed else '❌'} {result.test_name}: {result.message}", "SUCCESS" if result.passed else "ERROR")
            await asyncio.sleep(0.5)
        
        return results
    
    async def run_stress_tests(self, sessions: int = 20, requests_per_session: int = 10) -> List[SessionTestResult]:
        """Run stress tests."""
        return [await self.test_concurrent_sessions_stress(sessions, requests_per_session)]
    
    def generate_report(self, results: List[SessionTestResult]) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        print("\n" + "="*70)
        print("📊 MCP SESSION & PERFORMANCE TEST REPORT")
        print("="*70)
        print(f"Time: {datetime.now().isoformat()}")
        print(f"Target: {self.mcp_url}")
        print()
        
        # Group results by category
        session_tests = [r for r in results if "Session" in r.test_name]
        tool_tests = [r for r in results if "Tool" in r.test_name]
        stress_tests = [r for r in results if "Stress" in r.test_name]
        
        # Display results by category
        for category, tests in [
            ("SESSION MANAGEMENT", session_tests),
            ("TOOL PERFORMANCE", tool_tests),
            ("STRESS TESTS", stress_tests)
        ]:
            if tests:
                print(f"\n{category}:")
                print("-" * 40)
                for test in tests:
                    status = "✅ PASS" if test.passed else "❌ FAIL"
                    print(f"{status} | {test.test_name}")
                    print(f"        {test.message}")
                    if test.duration_ms > 0:
                        print(f"        Duration: {test.duration_ms:.1f}ms")
                    if self.verbose and test.details:
                        if isinstance(test.details, dict):
                            for key, value in test.details.items():
                                print(f"        {key}: {value}")
                        else:
                            print(f"        Details: {test.details}")
        
        # Overall summary
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r.passed)
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print("\n" + "="*70)
        print("SUMMARY:")
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {total_tests - passed_tests}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if success_rate == 100:
            print("\n🎉 ALL TESTS PASSED - MCP SERVER FULLY COMPLIANT!")
        elif success_rate >= 80:
            print("\n⚠️ MOSTLY PASSING - Some issues need attention")
        else:
            print("\n❌ CRITICAL ISSUES - Major problems detected")
        
        print("="*70)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "target": self.mcp_url,
            "summary": {
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": total_tests - passed_tests,
                "success_rate": success_rate
            },
            "results": [
                {
                    "test": r.test_name,
                    "passed": r.passed,
                    "message": r.message,
                    "duration_ms": r.duration_ms,
                    "details": r.details
                }
                for r in results
            ]
        }


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MCP Session Management & Performance Stress Test"
    )
    parser.add_argument(
        "--url",
        default="https://auth.atratest.org",
        help="Target MCP server URL"
    )
    parser.add_argument(
        "--mode",
        choices=["quick", "sessions", "tools", "stress", "all"],
        default="quick",
        help="Test mode"
    )
    parser.add_argument(
        "--sessions",
        type=int,
        default=20,
        help="Number of concurrent sessions for stress test"
    )
    parser.add_argument(
        "--requests-per-session",
        type=int,
        default=10,
        help="Requests per session in stress test"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="Iterations for performance tests"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    
    args = parser.parse_args()
    
    # Create test suite
    suite = MCPSessionStressTest(args.url, verbose=args.verbose)
    
    # Run tests based on mode
    results = []
    
    if args.mode in ["quick", "sessions", "all"]:
        print("\n🔐 Running Session Management Tests...")
        session_results = await suite.run_session_tests()
        results.extend(session_results)
    
    if args.mode in ["quick", "tools", "all"]:
        print("\n🔧 Running Tool Performance Tests...")
        tool_results = await suite.run_tool_tests(args.iterations)
        results.extend(tool_results)
    
    if args.mode in ["stress", "all"]:
        print("\n💪 Running Stress Tests...")
        stress_results = await suite.run_stress_tests(args.sessions, args.requests_per_session)
        results.extend(stress_results)
    
    # Generate report
    report = suite.generate_report(results)
    
    if args.json:
        print("\n" + json.dumps(report, indent=2))
    
    # Exit code based on results
    sys.exit(0 if report["summary"]["success_rate"] == 100 else 1)


if __name__ == "__main__":
    asyncio.run(main())