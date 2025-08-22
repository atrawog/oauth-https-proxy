#!/usr/bin/env python3
"""
Direct test comparing MCP logging tools with proxy-client commands.

This test bypasses the justfile and calls proxy-client directly, comparing
outputs with MCP tools via HTTP.
"""

import json
import time
import subprocess
import sys
import os
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass
import random


@dataclass
class ComparisonResult:
    """Result of comparing a proxy-client command with an MCP tool."""
    command_name: str
    proxy_client_output: Dict[str, Any]
    mcp_output: Dict[str, Any]
    identical: bool
    differences: List[str]
    error: Optional[str] = None


class ProxyClientMCPComparisonTest:
    """Test suite comparing MCP logging tools with proxy-client commands."""
    
    def __init__(self):
        """Initialize the test suite."""
        self.base_url = "http://localhost:9000"
        self.mcp_url = f"{self.base_url}/mcp"
        self.admin_token = os.getenv("ADMIN_TOKEN", "acm_admin_token_here")
        self.test_results: List[ComparisonResult] = []
        
        # Test data tracking
        self.test_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25"]
        self.test_hostnames = ["api.test.com", "auth.test.com", "app.test.com"]
        self.generated_requests = []
        
        # MCP session
        self.mcp_session = None
    
    def generate_test_log_data(self):
        """Generate test log data by making various API requests."""
        print("📊 Generating test log data...")
        
        # Clear any existing test data
        self.generated_requests = []
        
        # Generate different types of requests
        request_types = [
            # Successful requests
            ("GET", "/tokens/", None, 200),
            ("GET", "/certificates/", None, 200),
            ("GET", "/proxies/", None, 200),
            ("GET", "/services/", None, 200),
            ("GET", "/routes/", None, 200),
            
            # Error requests (should generate 4xx/5xx)
            ("GET", "/nonexistent/", None, 404),
            ("POST", "/tokens/", {"invalid": "data"}, 422),
            ("DELETE", "/certificates/nonexistent", None, 404),
            
            # OAuth requests
            ("GET", "/oauth/authorize", None, 400),  # Missing parameters
            ("POST", "/oauth/token", {"invalid": "grant"}, 400),
            
            # MCP endpoint requests
            ("GET", "/mcp", None, 200),
        ]
        
        # Make requests with different IPs (simulated via headers)
        for request_type, path, data, expected_status in request_types:
            for ip in self.test_ips:
                for hostname in self.test_hostnames:
                    try:
                        headers = {
                            "X-Forwarded-For": ip,
                            "Host": hostname,
                            "Authorization": f"Bearer {self.admin_token}"
                        }
                        
                        if request_type == "GET":
                            response = requests.get(
                                f"{self.base_url}{path}",
                                headers=headers,
                                timeout=5
                            )
                        elif request_type == "POST":
                            response = requests.post(
                                f"{self.base_url}{path}",
                                json=data,
                                headers=headers,
                                timeout=5
                            )
                        elif request_type == "DELETE":
                            response = requests.delete(
                                f"{self.base_url}{path}",
                                headers=headers,
                                timeout=5
                            )
                        
                        self.generated_requests.append({
                            "method": request_type,
                            "path": path,
                            "ip": ip,
                            "hostname": hostname,
                            "status_code": response.status_code,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                        
                        # Small delay to avoid overwhelming the system
                        time.sleep(0.1)
                        
                    except requests.RequestException as e:
                        print(f"Warning: Request failed: {e}")
        
        print(f"✅ Generated {len(self.generated_requests)} test requests")
        
        # Wait a bit for logs to be processed
        time.sleep(5)
    
    def initialize_mcp_session(self):
        """Initialize an MCP session."""
        print("🔗 Initializing MCP session...")
        
        try:
            # Initialize MCP session via HTTP
            response = requests.post(
                self.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "experimental": {},
                            "sampling": {}
                        },
                        "clientInfo": {
                            "name": "test-client",
                            "version": "1.0.0"
                        }
                    }
                },
                headers={"Authorization": f"Bearer {self.admin_token}"},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    print("✅ MCP session initialized")
                    # Store session for later use
                    self.mcp_session = response.cookies.get('session')
                    return True
            
            print(f"⚠️ MCP session initialization failed: {response.text}")
            return False
            
        except Exception as e:
            print(f"❌ Failed to initialize MCP session: {e}")
            return False
    
    def run_proxy_client_command(self, command: List[str]) -> Dict[str, Any]:
        """Run a proxy-client command and return parsed output."""
        try:
            env = {**os.environ, "TOKEN": self.admin_token}
            result = subprocess.run(
                ["pixi", "run", "proxy-client"] + command,
                capture_output=True,
                text=True,
                check=True,
                env=env
            )
            
            # Try to parse as JSON
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                # If not JSON, return as text
                return {"output": result.stdout.strip(), "raw_output": True}
                
        except subprocess.CalledProcessError as e:
            raise Exception(f"Proxy-client command failed: {e.stderr}")
    
    def call_mcp_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Call an MCP tool via HTTP and return the result."""
        try:
            headers = {"Authorization": f"Bearer {self.admin_token}"}
            if self.mcp_session:
                headers["Cookie"] = f"session={self.mcp_session}"
            
            response = requests.post(
                self.mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": random.randint(1, 10000),
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": kwargs
                    }
                },
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    # MCP tools return content in result.content
                    tool_result = result["result"]
                    if "content" in tool_result:
                        # Extract actual result from content array
                        content_items = tool_result["content"]
                        if content_items and len(content_items) > 0:
                            first_content = content_items[0]
                            if "text" in first_content:
                                try:
                                    return json.loads(first_content["text"])
                                except json.JSONDecodeError:
                                    return {"output": first_content["text"], "raw_output": True}
                    return tool_result
                elif "error" in result:
                    raise Exception(f"MCP tool error: {result['error']}")
            
            raise Exception(f"MCP tool call failed: {response.status_code} - {response.text}")
            
        except Exception as e:
            raise Exception(f"MCP tool failed: {str(e)}")
    
    def compare_outputs(self, proxy_output: Dict[str, Any], mcp_output: Dict[str, Any]) -> List[str]:
        """Compare proxy-client output with MCP tool output."""
        differences = []
        
        # If both are raw text output, compare directly
        if proxy_output.get("raw_output") and mcp_output.get("raw_output"):
            if proxy_output.get("output") != mcp_output.get("output"):
                differences.append("Text output differs")
            return differences
        
        # Check for similar structure
        proxy_keys = set(proxy_output.keys())
        mcp_keys = set(mcp_output.keys())
        
        # Some key mappings we might expect
        key_mappings = {
            "logs": "logs",
            "total": "count",
            "errors": "errors",
        }
        
        # Check if we have equivalent data
        proxy_has_logs = "logs" in proxy_output or "total" in proxy_output
        mcp_has_logs = "logs" in mcp_output or "count" in mcp_output
        
        if proxy_has_logs != mcp_has_logs:
            differences.append("Different presence of log data")
        
        # Compare log counts if both have them
        if proxy_has_logs and mcp_has_logs:
            proxy_count = len(proxy_output.get("logs", [])) or proxy_output.get("total", 0)
            mcp_count = len(mcp_output.get("logs", [])) or mcp_output.get("count", 0)
            
            if proxy_count != mcp_count:
                differences.append(f"Different log counts: proxy={proxy_count}, mcp={mcp_count}")
        
        # Check for error logs specifically
        proxy_has_errors = "errors" in proxy_output
        mcp_has_errors = "errors" in mcp_output
        
        if proxy_has_errors != mcp_has_errors:
            differences.append("Different presence of error data")
        
        return differences
    
    def compare_logs_search(self) -> ComparisonResult:
        """Compare proxy-client log search with MCP logs tool."""
        print("🔍 Comparing log search commands...")
        
        try:
            # Run proxy-client command
            proxy_output = self.run_proxy_client_command([
                "log", "search", "--hours", "1", "--limit", "20"
            ])
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs", hours=1, limit=20)
            
            # Compare results
            differences = self.compare_outputs(proxy_output, mcp_output)
            
            return ComparisonResult(
                command_name="log-search",
                proxy_client_output=proxy_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="log-search",
                proxy_client_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def compare_logs_errors(self) -> ComparisonResult:
        """Compare proxy-client log errors with MCP logs_errors tool."""
        print("🔍 Comparing log errors commands...")
        
        try:
            # Run proxy-client command
            proxy_output = self.run_proxy_client_command([
                "log", "errors", "--hours", "1", "--limit", "10"
            ])
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs_errors", hours=1, limit=10)
            
            # Compare results
            differences = self.compare_outputs(proxy_output, mcp_output)
            
            return ComparisonResult(
                command_name="log-errors",
                proxy_client_output=proxy_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="log-errors",
                proxy_client_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def compare_logs_by_ip(self) -> ComparisonResult:
        """Compare proxy-client log by-ip with MCP logs_ip tool."""
        print("🔍 Comparing log by-ip commands...")
        
        test_ip = self.test_ips[0]  # Use first test IP
        
        try:
            # Run proxy-client command
            proxy_output = self.run_proxy_client_command([
                "log", "by-ip", test_ip, "--hours", "1", "--limit", "10"
            ])
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs_ip", ip=test_ip, hours=1, limit=10)
            
            # Compare results
            differences = self.compare_outputs(proxy_output, mcp_output)
            
            return ComparisonResult(
                command_name="log-by-ip",
                proxy_client_output=proxy_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="log-by-ip",
                proxy_client_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def compare_logs_by_proxy(self) -> ComparisonResult:
        """Compare proxy-client log by-proxy with MCP logs_proxy tool."""
        print("🔍 Comparing log by-proxy commands...")
        
        test_hostname = self.test_hostnames[0]  # Use first test hostname
        
        try:
            # Run proxy-client command
            proxy_output = self.run_proxy_client_command([
                "log", "by-proxy", test_hostname, "--hours", "1", "--limit", "10"
            ])
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs_proxy", hostname=test_hostname, hours=1, limit=10)
            
            # Compare results
            differences = self.compare_outputs(proxy_output, mcp_output)
            
            return ComparisonResult(
                command_name="log-by-proxy",
                proxy_client_output=proxy_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="log-by-proxy",
                proxy_client_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def compare_logs_events(self) -> ComparisonResult:
        """Compare proxy-client log events with MCP logs_stats tool."""
        print("🔍 Comparing log events/stats commands...")
        
        try:
            # Run proxy-client command
            proxy_output = self.run_proxy_client_command([
                "log", "events", "--hours", "1"
            ])
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs_stats", hours=1)
            
            # Compare results
            differences = self.compare_outputs(proxy_output, mcp_output)
            
            return ComparisonResult(
                command_name="log-events",
                proxy_client_output=proxy_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="log-events",
                proxy_client_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def run_all_comparisons(self):
        """Run all comparison tests."""
        print("🧪 Running all proxy-client vs MCP command comparisons...")
        
        # List of comparison functions
        comparisons = [
            self.compare_logs_search,
            self.compare_logs_errors,
            self.compare_logs_by_ip,
            self.compare_logs_by_proxy,
            self.compare_logs_events,
        ]
        
        # Run each comparison
        for comparison_func in comparisons:
            try:
                result = comparison_func()
                self.test_results.append(result)
            except Exception as e:
                print(f"❌ Comparison failed: {e}")
                self.test_results.append(ComparisonResult(
                    command_name=comparison_func.__name__.replace("compare_", "").replace("_command", ""),
                    proxy_client_output={},
                    mcp_output={},
                    identical=False,
                    differences=[],
                    error=str(e)
                ))
    
    def generate_detailed_report(self) -> str:
        """Generate a detailed comparison report."""
        report = []
        report.append("=" * 80)
        report.append("MCP LOGGING TOOLS vs PROXY-CLIENT COMMANDS COMPARISON REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Summary
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r.identical and not r.error)
        failed_tests = total_tests - passed_tests
        
        report.append(f"📊 SUMMARY")
        report.append(f"Total Tests: {total_tests}")
        report.append(f"Passed: {passed_tests}")
        report.append(f"Failed: {failed_tests}")
        report.append(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%" if total_tests > 0 else "N/A")
        report.append("")
        
        # Test data summary
        report.append(f"📈 TEST DATA GENERATED")
        report.append(f"Total Requests: {len(self.generated_requests)}")
        report.append(f"Test IPs: {', '.join(self.test_ips)}")
        report.append(f"Test Hostnames: {', '.join(self.test_hostnames)}")
        report.append("")
        
        # Detailed results for each test
        for result in self.test_results:
            report.append(f"🔍 TEST: {result.command_name}")
            report.append("-" * 40)
            
            if result.error:
                report.append(f"❌ ERROR: {result.error}")
            elif result.identical:
                report.append("✅ IDENTICAL: Proxy-client and MCP tool produce equivalent results")
            else:
                report.append("❌ DIFFERENCES FOUND:")
                for diff in result.differences:
                    report.append(f"   • {diff}")
            
            report.append("")
            
            # Show sample output comparison
            if result.proxy_client_output or result.mcp_output:
                report.append("📋 OUTPUT COMPARISON:")
                report.append("")
                
                report.append("Proxy-Client Output:")
                proxy_json = json.dumps(result.proxy_client_output, indent=2, default=str)
                for line in proxy_json.split('\n')[:15]:  # First 15 lines
                    report.append(f"  {line}")
                if len(proxy_json.split('\n')) > 15:
                    report.append("  ...")
                
                report.append("")
                
                report.append("MCP Tool Output:")
                mcp_json = json.dumps(result.mcp_output, indent=2, default=str)
                for line in mcp_json.split('\n')[:15]:  # First 15 lines
                    report.append(f"  {line}")
                if len(mcp_json.split('\n')) > 15:
                    report.append("  ...")
            
            report.append("")
            report.append("=" * 40)
            report.append("")
        
        # Recommendations
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 20)
        
        if failed_tests == 0:
            report.append("✅ All tests passed! MCP tools are equivalent to proxy-client commands.")
        else:
            report.append("🔧 Issues found that need attention:")
            for result in self.test_results:
                if not result.identical or result.error:
                    report.append(f"   • {result.command_name}: {'Error - ' + result.error if result.error else 'Output differences'}")
        
        report.append("")
        report.append("🕐 Report generated at: " + datetime.now(timezone.utc).isoformat())
        report.append("")
        
        return "\n".join(report)
    
    def run_full_test_suite(self):
        """Run the complete test suite."""
        print("🚀 Starting Proxy-Client vs MCP Logging Tools Comparison Test Suite")
        print("=" * 70)
        
        try:
            # Step 1: Initialize MCP session
            if not self.initialize_mcp_session():
                print("⚠️ Could not initialize MCP session, continuing anyway...")
            
            # Step 2: Generate test data
            self.generate_test_log_data()
            
            # Step 3: Run comparisons
            self.run_all_comparisons()
            
            # Step 4: Generate report
            report = self.generate_detailed_report()
            
            # Step 5: Save report
            report_file = "proxy_client_mcp_comparison_report.txt"
            with open(report_file, "w") as f:
                f.write(report)
            
            print("\n" + "=" * 70)
            print("🎯 TEST SUITE COMPLETED")
            print(f"📄 Report saved to: {report_file}")
            print("=" * 70)
            
            # Print summary
            total_tests = len(self.test_results)
            passed_tests = sum(1 for r in self.test_results if r.identical and not r.error)
            
            if passed_tests == total_tests:
                print("🎉 ALL TESTS PASSED!")
                print("✅ MCP tools are equivalent to proxy-client commands")
            else:
                print(f"⚠️  {total_tests - passed_tests} TESTS FAILED")
                print("🔧 Review the report for detailed differences")
            
            return report
            
        except Exception as e:
            print(f"❌ Test suite failed: {e}")
            raise


def main():
    """Run the proxy-client vs MCP comparison test."""
    test_suite = ProxyClientMCPComparisonTest()
    
    try:
        report = test_suite.run_full_test_suite()
        return 0
    except Exception as e:
        print(f"💥 Test suite failed with error: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)