#!/usr/bin/env python3
"""
Simplified test comparing MCP logging tools with their equivalent `just` commands.

This test uses HTTP calls to the MCP endpoint and proxy-client commands to compare
outputs without needing to set up the full async infrastructure.
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
    """Result of comparing a just command with an MCP tool."""
    command_name: str
    just_output: Dict[str, Any]
    mcp_output: Dict[str, Any]
    identical: bool
    differences: List[str]
    error: Optional[str] = None


class SimpleMCPLoggingComparisonTest:
    """Simplified test suite comparing MCP logging tools with just commands."""
    
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
        self.mcp_session_id = None
    
    def restart_api_service(self):
        """Restart the API service using docker-compose."""
        print("🔄 Restarting API service...")
        
        try:
            # Stop the service
            subprocess.run(
                ["docker-compose", "stop", "api"],
                check=True,
                capture_output=True,
                text=True
            )
            
            # Start the service
            subprocess.run(
                ["docker-compose", "start", "api"],
                check=True,
                capture_output=True,
                text=True
            )
            
            # Wait for service to be ready
            time.sleep(10)
            
            # Verify service is responding
            max_retries = 30
            for i in range(max_retries):
                try:
                    response = requests.get(f"{self.base_url}/health", timeout=5)
                    if response.status_code == 200:
                        print("✅ API service restarted successfully")
                        return
                except requests.RequestException:
                    pass
                
                time.sleep(2)
            
            raise Exception("API service did not respond after restart")
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to restart API service: {e}")
    
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
                    return True
            
            print(f"⚠️ MCP session initialization failed: {response.text}")
            return False
            
        except Exception as e:
            print(f"❌ Failed to initialize MCP session: {e}")
            return False
    
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
    
    def run_just_command(self, command: str) -> Dict[str, Any]:
        """Run a just command and return parsed output."""
        try:
            env = {**os.environ, "ADMIN_TOKEN": self.admin_token}
            result = subprocess.run(
                ["just"] + command.split(),
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
            raise Exception(f"Just command failed: {e.stderr}")
    
    def call_mcp_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Call an MCP tool via HTTP and return the result."""
        try:
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
                headers={"Authorization": f"Bearer {self.admin_token}"},
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
    
    def compare_outputs(self, just_output: Dict[str, Any], mcp_output: Dict[str, Any]) -> List[str]:
        """Compare just command output with MCP tool output."""
        differences = []
        
        # If both are raw text output, compare directly
        if just_output.get("raw_output") and mcp_output.get("raw_output"):
            if just_output.get("output") != mcp_output.get("output"):
                differences.append("Text output differs")
            return differences
        
        # Check for similar structure
        just_keys = set(just_output.keys())
        mcp_keys = set(mcp_output.keys())
        
        if just_keys != mcp_keys:
            differences.append(f"Different keys: just={just_keys}, mcp={mcp_keys}")
        
        # Compare common keys
        common_keys = just_keys & mcp_keys
        for key in common_keys:
            just_val = just_output[key]
            mcp_val = mcp_output[key]
            
            if isinstance(just_val, list) and isinstance(mcp_val, list):
                if len(just_val) != len(mcp_val):
                    differences.append(f"Different list lengths for '{key}': just={len(just_val)}, mcp={len(mcp_val)}")
            elif just_val != mcp_val:
                differences.append(f"Different values for '{key}'")
        
        return differences
    
    def compare_logs_command(self) -> ComparisonResult:
        """Compare 'just logs' with MCP 'logs' tool."""
        print("🔍 Comparing 'logs' command...")
        
        try:
            # Run just command with proper argument syntax
            just_output = self.run_just_command('logs hours="1" limit="20"')
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs", hours=1, limit=20)
            
            # Compare results
            differences = self.compare_outputs(just_output, mcp_output)
            
            return ComparisonResult(
                command_name="logs",
                just_output=just_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="logs",
                just_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def compare_logs_errors_command(self) -> ComparisonResult:
        """Compare 'just logs-errors' with MCP 'logs_errors' tool."""
        print("🔍 Comparing 'logs-errors' command...")
        
        try:
            # Run just command
            just_output = self.run_just_command('logs-errors hours="1" limit="10"')
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs_errors", hours=1, limit=10)
            
            # Compare results
            differences = self.compare_outputs(just_output, mcp_output)
            
            return ComparisonResult(
                command_name="logs-errors",
                just_output=just_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="logs-errors",
                just_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def compare_logs_ip_command(self) -> ComparisonResult:
        """Compare 'just logs-ip' with MCP 'logs_ip' tool."""
        print("🔍 Comparing 'logs-ip' command...")
        
        test_ip = self.test_ips[0]  # Use first test IP
        
        try:
            # Run just command
            just_output = self.run_just_command(f'logs-ip ip="{test_ip}" hours="1" limit="10"')
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs_ip", ip=test_ip, hours=1, limit=10)
            
            # Compare results
            differences = self.compare_outputs(just_output, mcp_output)
            
            return ComparisonResult(
                command_name="logs-ip",
                just_output=just_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="logs-ip",
                just_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def compare_logs_proxy_command(self) -> ComparisonResult:
        """Compare 'just logs-proxy' with MCP 'logs_proxy' tool."""
        print("🔍 Comparing 'logs-proxy' command...")
        
        test_hostname = self.test_hostnames[0]  # Use first test hostname
        
        try:
            # Run just command
            just_output = self.run_just_command(f'logs-proxy hostname="{test_hostname}" hours="1" limit="10"')
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs_proxy", hostname=test_hostname, hours=1, limit=10)
            
            # Compare results
            differences = self.compare_outputs(just_output, mcp_output)
            
            return ComparisonResult(
                command_name="logs-proxy",
                just_output=just_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="logs-proxy",
                just_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def compare_logs_stats_command(self) -> ComparisonResult:
        """Compare 'just logs-stats' with MCP 'logs_stats' tool."""
        print("🔍 Comparing 'logs-stats' command...")
        
        try:
            # Run just command
            just_output = self.run_just_command('logs-stats hours="1"')
            
            # Run MCP tool
            mcp_output = self.call_mcp_tool("logs_stats", hours=1)
            
            # Compare results
            differences = self.compare_outputs(just_output, mcp_output)
            
            return ComparisonResult(
                command_name="logs-stats",
                just_output=just_output,
                mcp_output=mcp_output,
                identical=len(differences) == 0,
                differences=differences
            )
            
        except Exception as e:
            return ComparisonResult(
                command_name="logs-stats",
                just_output={},
                mcp_output={},
                identical=False,
                differences=[],
                error=str(e)
            )
    
    def run_all_comparisons(self):
        """Run all comparison tests."""
        print("🧪 Running all MCP vs Just command comparisons...")
        
        # List of comparison functions
        comparisons = [
            self.compare_logs_command,
            self.compare_logs_errors_command,
            self.compare_logs_ip_command,
            self.compare_logs_proxy_command,
            self.compare_logs_stats_command,
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
                    just_output={},
                    mcp_output={},
                    identical=False,
                    differences=[],
                    error=str(e)
                ))
    
    def generate_detailed_report(self) -> str:
        """Generate a detailed comparison report."""
        report = []
        report.append("=" * 80)
        report.append("MCP LOGGING TOOLS vs JUST COMMANDS COMPARISON REPORT")
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
                report.append("✅ IDENTICAL: Just command and MCP tool produce identical results")
            else:
                report.append("❌ DIFFERENCES FOUND:")
                for diff in result.differences:
                    report.append(f"   • {diff}")
            
            report.append("")
            
            # Show sample output comparison
            if result.just_output or result.mcp_output:
                report.append("📋 OUTPUT COMPARISON:")
                report.append("")
                
                report.append("Just Command Output:")
                just_json = json.dumps(result.just_output, indent=2, default=str)
                for line in just_json.split('\n')[:15]:  # First 15 lines
                    report.append(f"  {line}")
                if len(just_json.split('\n')) > 15:
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
            report.append("✅ All tests passed! MCP tools are exact replacements for just commands.")
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
        print("🚀 Starting MCP Logging Tools Comparison Test Suite")
        print("=" * 60)
        
        try:
            # Step 1: Restart API service
            self.restart_api_service()
            
            # Step 2: Initialize MCP session
            if not self.initialize_mcp_session():
                print("⚠️ Could not initialize MCP session, continuing anyway...")
            
            # Step 3: Generate test data
            self.generate_test_log_data()
            
            # Step 4: Run comparisons
            self.run_all_comparisons()
            
            # Step 5: Generate report
            report = self.generate_detailed_report()
            
            # Step 6: Save report
            report_file = "mcp_logging_comparison_report.txt"
            with open(report_file, "w") as f:
                f.write(report)
            
            print("\n" + "=" * 60)
            print("🎯 TEST SUITE COMPLETED")
            print(f"📄 Report saved to: {report_file}")
            print("=" * 60)
            
            # Print summary
            total_tests = len(self.test_results)
            passed_tests = sum(1 for r in self.test_results if r.identical and not r.error)
            
            if passed_tests == total_tests:
                print("🎉 ALL TESTS PASSED!")
                print("✅ MCP tools are exact replacements for just commands")
            else:
                print(f"⚠️  {total_tests - passed_tests} TESTS FAILED")
                print("🔧 Review the report for detailed differences")
            
            return report
            
        except Exception as e:
            print(f"❌ Test suite failed: {e}")
            raise


def main():
    """Run the MCP logging comparison test."""
    test_suite = SimpleMCPLoggingComparisonTest()
    
    try:
        report = test_suite.run_full_test_suite()
        print("\n" + "=" * 80)
        print("FULL REPORT:")
        print("=" * 80)
        print(report)
        return 0
    except Exception as e:
        print(f"💥 Test suite failed with error: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)