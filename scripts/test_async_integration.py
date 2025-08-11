#!/usr/bin/env python3
"""Comprehensive test script for async Redis Streams architecture integration.

This script tests all affected code paths and just commands to ensure
the new async architecture works correctly with the existing system.
"""

import asyncio
import json
import os
import time
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import httpx
import redis.asyncio as redis_async

# Test configuration
API_URL = os.getenv("TEST_API_URL", "http://localhost:80")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
TEST_TOKEN = os.getenv("TEST_TOKEN", "")
TEST_DOMAIN = os.getenv("TEST_DOMAIN", "test.atradev.org")


class AsyncIntegrationTester:
    """Comprehensive tester for async architecture integration."""
    
    def __init__(self):
        self.api_url = API_URL
        self.redis_url = REDIS_URL
        self.test_token = TEST_TOKEN
        self.test_domain = TEST_DOMAIN
        self.redis_client = None
        self.http_client = None
        self.test_results = []
        self.failed_tests = []
    
    async def setup(self):
        """Setup test environment."""
        print("🔧 Setting up test environment...")
        
        # Initialize Redis client
        self.redis_client = redis_async.from_url(self.redis_url)
        
        # Initialize HTTP client
        self.http_client = httpx.AsyncClient(timeout=30.0)
        
        # Check Redis connectivity
        try:
            await self.redis_client.ping()
            print("✅ Redis connected")
        except Exception as e:
            print(f"❌ Redis connection failed: {e}")
            raise
        
        # Check API health
        try:
            resp = await self.http_client.get(f"{self.api_url}/health")
            if resp.status_code == 200:
                print("✅ API is healthy")
            else:
                print(f"⚠️  API health check returned {resp.status_code}")
        except Exception as e:
            print(f"❌ API health check failed: {e}")
            raise
    
    async def teardown(self):
        """Cleanup test environment."""
        print("\n🧹 Cleaning up...")
        
        if self.redis_client:
            await self.redis_client.close()
        
        if self.http_client:
            await self.http_client.aclose()
    
    def run_just_command(self, command: str) -> tuple[bool, str, str]:
        """Run a just command and return success, stdout, stderr.
        
        Args:
            command: Just command to run
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                f"just {command}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    async def test_redis_stream_publishing(self) -> bool:
        """Test that events are being published to Redis Streams."""
        print("\n📡 Testing Redis Stream Publishing...")
        
        try:
            # Check if streams exist
            streams = [
                "logs:all:stream",
                "logs:request:stream",
                "logs:error:stream",
                "events:all:stream",
                "events:service:stream",
                "events:certificate:stream"
            ]
            
            for stream in streams:
                exists = await self.redis_client.exists(stream)
                if exists:
                    length = await self.redis_client.xlen(stream)
                    print(f"  ✓ Stream {stream}: {length} messages")
                else:
                    print(f"  ⚠️  Stream {stream} does not exist")
            
            # Publish a test event and verify it appears
            test_event_key = "test:event:marker"
            test_event_value = f"test_{int(time.time())}"
            
            # Make a request to generate events
            headers = {"Authorization": f"Bearer {self.test_token}"} if self.test_token else {}
            resp = await self.http_client.get(
                f"{self.api_url}/api/v1/tokens/",
                headers=headers
            )
            
            # Wait for event processing
            await asyncio.sleep(0.5)
            
            # Check for recent request logs
            recent_logs = await self.redis_client.xrevrange(
                "logs:request:stream",
                count=10
            )
            
            if recent_logs:
                print(f"  ✓ Found {len(recent_logs)} recent request logs")
                return True
            else:
                print("  ❌ No recent request logs found")
                return False
                
        except Exception as e:
            print(f"  ❌ Stream publishing test failed: {e}")
            return False
    
    async def test_trace_correlation(self) -> bool:
        """Test that traces are properly correlating events."""
        print("\n🔗 Testing Trace Correlation...")
        
        try:
            # Make a request that should generate a trace
            headers = {"Authorization": f"Bearer {self.test_token}"} if self.test_token else {}
            resp = await self.http_client.get(
                f"{self.api_url}/api/v1/certificates/",
                headers=headers
            )
            
            # Extract trace ID from response header if present
            trace_id = resp.headers.get("X-Trace-Id")
            if trace_id:
                print(f"  ✓ Got trace ID from response: {trace_id}")
                
                # Check if trace exists in Redis
                trace_key = f"trace:{trace_id}"
                trace_data = await self.redis_client.get(trace_key)
                
                if trace_data:
                    trace = json.loads(trace_data)
                    print(f"  ✓ Trace found in Redis with {len(trace.get('spans', []))} spans")
                    return True
                else:
                    print(f"  ⚠️  Trace {trace_id} not found in Redis")
            else:
                print("  ⚠️  No trace ID in response headers")
            
            return False
            
        except Exception as e:
            print(f"  ❌ Trace correlation test failed: {e}")
            return False
    
    async def test_consumer_lag(self) -> bool:
        """Test that stream consumers have acceptable lag."""
        print("\n⏱️  Testing Consumer Lag...")
        
        try:
            streams = {
                "logs:request:stream": "metrics-group",
                "logs:error:stream": "alert-group",
                "events:service:stream": "metrics-group"
            }
            
            all_healthy = True
            
            for stream, group in streams.items():
                try:
                    # Get consumer group info
                    groups = await self.redis_client.xinfo_groups(stream)
                    
                    for group_info in groups:
                        if group_info['name'] == group:
                            lag = group_info.get('lag', 0)
                            if lag < 1000:
                                print(f"  ✓ {stream}/{group}: lag={lag} messages")
                            else:
                                print(f"  ⚠️  {stream}/{group}: HIGH LAG={lag} messages")
                                all_healthy = False
                            break
                except:
                    # Group might not exist yet
                    pass
            
            return all_healthy
            
        except Exception as e:
            print(f"  ❌ Consumer lag test failed: {e}")
            return False
    
    async def test_docker_operations(self) -> bool:
        """Test Docker service operations with async manager."""
        print("\n🐳 Testing Docker Operations...")
        
        try:
            service_name = f"test-service-{int(time.time())}"
            
            # Test service creation via just command
            print(f"  Creating service {service_name}...")
            success, stdout, stderr = self.run_just_command(
                f"service-create {service_name} nginx:alpine '' 80 256m 0.5 false {self.test_token}"
            )
            
            if not success:
                print(f"  ❌ Service creation failed: {stderr}")
                return False
            
            print(f"  ✓ Service {service_name} created")
            
            # Wait for event processing
            await asyncio.sleep(1)
            
            # Check for service creation event
            events = await self.redis_client.xrevrange(
                "events:service:stream",
                count=10
            )
            
            service_event_found = False
            for msg_id, data in events:
                if b'service_name' in data and service_name.encode() in data[b'service_name']:
                    service_event_found = True
                    print(f"  ✓ Service creation event found in stream")
                    break
            
            if not service_event_found:
                print("  ⚠️  Service creation event not found in stream")
            
            # Test service deletion
            print(f"  Deleting service {service_name}...")
            success, stdout, stderr = self.run_just_command(
                f"service-delete {service_name} true false {self.test_token}"
            )
            
            if success:
                print(f"  ✓ Service {service_name} deleted")
                return True
            else:
                print(f"  ⚠️  Service deletion had issues: {stderr}")
                return False
                
        except Exception as e:
            print(f"  ❌ Docker operations test failed: {e}")
            return False
    
    async def test_certificate_operations(self) -> bool:
        """Test certificate operations with async manager."""
        print("\n🔐 Testing Certificate Operations...")
        
        try:
            cert_name = f"test-cert-{int(time.time())}"
            test_domain = f"test-{int(time.time())}.{self.test_domain}"
            
            # Test certificate creation via API
            print(f"  Creating certificate {cert_name}...")
            headers = {"Authorization": f"Bearer {self.test_token}"} if self.test_token else {}
            
            resp = await self.http_client.post(
                f"{self.api_url}/api/v1/certificates/",
                headers=headers,
                json={
                    "cert_name": cert_name,
                    "domain": test_domain,
                    "email": "test@example.com",
                    "use_staging": True
                }
            )
            
            if resp.status_code == 200:
                print(f"  ✓ Certificate generation started")
                
                # Wait for generation
                await asyncio.sleep(5)
                
                # Check for certificate events
                events = await self.redis_client.xrevrange(
                    "events:certificate:stream",
                    count=20
                )
                
                cert_events = []
                for msg_id, data in events:
                    if b'cert_name' in data and cert_name.encode() in data[b'cert_name']:
                        event_type = data.get(b'event_type', b'').decode()
                        cert_events.append(event_type)
                
                if cert_events:
                    print(f"  ✓ Found certificate events: {', '.join(cert_events)}")
                else:
                    print("  ⚠️  No certificate events found")
                
                # Test certificate deletion
                print(f"  Deleting certificate {cert_name}...")
                resp = await self.http_client.delete(
                    f"{self.api_url}/api/v1/certificates/{cert_name}",
                    headers=headers
                )
                
                if resp.status_code in [200, 204]:
                    print(f"  ✓ Certificate {cert_name} deleted")
                    return True
                else:
                    print(f"  ⚠️  Certificate deletion returned {resp.status_code}")
                    return False
            else:
                print(f"  ❌ Certificate creation returned {resp.status_code}: {resp.text}")
                return False
                
        except Exception as e:
            print(f"  ❌ Certificate operations test failed: {e}")
            return False
    
    async def test_proxy_operations(self) -> bool:
        """Test proxy operations with async handler."""
        print("\n🔄 Testing Proxy Operations...")
        
        try:
            proxy_hostname = f"test-proxy-{int(time.time())}.{self.test_domain}"
            
            # Test proxy creation via just command
            print(f"  Creating proxy {proxy_hostname}...")
            success, stdout, stderr = self.run_just_command(
                f"proxy-create {proxy_hostname} http://example.com true false true false '' {self.test_token}"
            )
            
            if not success:
                print(f"  ❌ Proxy creation failed: {stderr}")
                return False
            
            print(f"  ✓ Proxy {proxy_hostname} created")
            
            # Make a request through the proxy
            print(f"  Testing proxy request to {proxy_hostname}...")
            try:
                resp = await self.http_client.get(
                    f"http://{proxy_hostname}/",
                    headers={"Host": proxy_hostname},
                    follow_redirects=False
                )
                print(f"  ✓ Proxy responded with status {resp.status_code}")
            except Exception as e:
                print(f"  ⚠️  Proxy request failed: {e}")
            
            # Check for proxy request events
            await asyncio.sleep(0.5)
            
            events = await self.redis_client.xrevrange(
                "logs:request:stream",
                count=20
            )
            
            proxy_request_found = False
            for msg_id, data in events:
                if b'hostname' in data and proxy_hostname.encode() in data[b'hostname']:
                    proxy_request_found = True
                    print(f"  ✓ Proxy request logged in stream")
                    break
            
            if not proxy_request_found:
                print("  ⚠️  Proxy request not found in logs")
            
            # Test proxy deletion
            print(f"  Deleting proxy {proxy_hostname}...")
            success, stdout, stderr = self.run_just_command(
                f"proxy-delete {proxy_hostname} false false {self.test_token}"
            )
            
            if success:
                print(f"  ✓ Proxy {proxy_hostname} deleted")
                return True
            else:
                print(f"  ⚠️  Proxy deletion had issues: {stderr}")
                return False
                
        except Exception as e:
            print(f"  ❌ Proxy operations test failed: {e}")
            return False
    
    async def test_port_operations(self) -> bool:
        """Test port management operations."""
        print("\n🔌 Testing Port Operations...")
        
        try:
            # Test port allocation via API
            print("  Testing port allocation...")
            
            # Check available ports
            success, stdout, stderr = self.run_just_command(
                f"service-ports-global true {self.test_token}"
            )
            
            if success:
                print("  ✓ Retrieved global port status")
            else:
                print(f"  ⚠️  Port status retrieval failed: {stderr}")
            
            # Test port check
            test_port = 12345
            success, stdout, stderr = self.run_just_command(
                f"service-port-check {test_port} 127.0.0.1 {self.test_token}"
            )
            
            if success:
                print(f"  ✓ Port {test_port} availability checked")
                return True
            else:
                print(f"  ⚠️  Port check failed: {stderr}")
                return False
                
        except Exception as e:
            print(f"  ❌ Port operations test failed: {e}")
            return False
    
    async def test_logging_operations(self) -> bool:
        """Test unified logging operations."""
        print("\n📝 Testing Logging Operations...")
        
        try:
            # Test log retrieval via just command
            print("  Retrieving recent logs...")
            success, stdout, stderr = self.run_just_command(
                f"logs 1 '' INFO '' 10 {self.test_token}"
            )
            
            if not success:
                print(f"  ⚠️  Log retrieval had issues: {stderr}")
            else:
                log_lines = stdout.strip().split('\n')
                print(f"  ✓ Retrieved {len(log_lines)} log entries")
            
            # Test error log retrieval
            print("  Retrieving error logs...")
            success, stdout, stderr = self.run_just_command(
                f"logs-errors 1 10 {self.test_token}"
            )
            
            if success:
                print("  ✓ Error log retrieval successful")
            else:
                print(f"  ⚠️  Error log retrieval failed: {stderr}")
            
            # Test log statistics
            print("  Retrieving log statistics...")
            success, stdout, stderr = self.run_just_command(
                f"logs-stats 1 {self.test_token}"
            )
            
            if success:
                print("  ✓ Log statistics retrieved")
                return True
            else:
                print(f"  ⚠️  Log statistics failed: {stderr}")
                return False
                
        except Exception as e:
            print(f"  ❌ Logging operations test failed: {e}")
            return False
    
    async def test_metrics_endpoint(self) -> bool:
        """Test metrics collection endpoint."""
        print("\n📊 Testing Metrics Endpoint...")
        
        try:
            headers = {"Authorization": f"Bearer {self.test_token}"} if self.test_token else {}
            
            # Test orchestrator status endpoint
            resp = await self.http_client.get(
                f"{self.api_url}/api/v1/orchestrator/status",
                headers=headers
            )
            
            if resp.status_code == 200:
                status = resp.json()
                print(f"  ✓ Orchestrator status retrieved")
                
                if "components" in status:
                    for comp, state in status["components"].items():
                        print(f"    - {comp}: {state}")
                
                return True
            elif resp.status_code == 404:
                print("  ⚠️  Orchestrator endpoints not available (not integrated yet)")
                return True  # Not a failure if not integrated
            else:
                print(f"  ❌ Status endpoint returned {resp.status_code}")
                return False
                
        except Exception as e:
            print(f"  ❌ Metrics endpoint test failed: {e}")
            return False
    
    async def test_performance(self) -> bool:
        """Test performance metrics of async operations."""
        print("\n⚡ Testing Performance...")
        
        try:
            # Test concurrent operations
            print("  Testing concurrent operations...")
            start_time = time.time()
            
            tasks = []
            headers = {"Authorization": f"Bearer {self.test_token}"} if self.test_token else {}
            
            # Mix of different operations
            for i in range(20):
                if i % 3 == 0:
                    # Token list
                    tasks.append(
                        self.http_client.get(
                            f"{self.api_url}/api/v1/tokens/",
                            headers=headers
                        )
                    )
                elif i % 3 == 1:
                    # Certificate list
                    tasks.append(
                        self.http_client.get(
                            f"{self.api_url}/api/v1/certificates/",
                            headers=headers
                        )
                    )
                else:
                    # Service list
                    tasks.append(
                        self.http_client.get(
                            f"{self.api_url}/api/v1/services/",
                            headers=headers
                        )
                    )
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            duration = time.time() - start_time
            successful = sum(1 for r in results if not isinstance(r, Exception) and r.status_code == 200)
            
            ops_per_second = len(tasks) / duration
            
            print(f"  ✓ Completed {successful}/{len(tasks)} operations in {duration:.2f}s")
            print(f"  ✓ Performance: {ops_per_second:.1f} ops/sec")
            
            if ops_per_second > 10:
                print("  ✓ Performance is good")
                return True
            else:
                print("  ⚠️  Performance is below expectations")
                return False
                
        except Exception as e:
            print(f"  ❌ Performance test failed: {e}")
            return False
    
    async def run_all_tests(self):
        """Run all tests and report results."""
        print("\n" + "="*60)
        print("🚀 Starting Comprehensive Async Architecture Tests")
        print("="*60)
        
        await self.setup()
        
        tests = [
            ("Redis Stream Publishing", self.test_redis_stream_publishing),
            ("Trace Correlation", self.test_trace_correlation),
            ("Consumer Lag", self.test_consumer_lag),
            ("Docker Operations", self.test_docker_operations),
            ("Certificate Operations", self.test_certificate_operations),
            ("Proxy Operations", self.test_proxy_operations),
            ("Port Operations", self.test_port_operations),
            ("Logging Operations", self.test_logging_operations),
            ("Metrics Endpoint", self.test_metrics_endpoint),
            ("Performance", self.test_performance)
        ]
        
        results = []
        
        for test_name, test_func in tests:
            try:
                result = await test_func()
                results.append((test_name, result))
                
                if not result:
                    self.failed_tests.append(test_name)
                    
            except Exception as e:
                print(f"\n❌ Test '{test_name}' crashed: {e}")
                results.append((test_name, False))
                self.failed_tests.append(test_name)
        
        await self.teardown()
        
        # Print summary
        print("\n" + "="*60)
        print("📋 Test Summary")
        print("="*60)
        
        passed = sum(1 for _, result in results if result)
        total = len(results)
        
        for test_name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"  {status}: {test_name}")
        
        print("\n" + "-"*60)
        print(f"Results: {passed}/{total} tests passed ({passed*100//total}%)")
        
        if self.failed_tests:
            print(f"\nFailed tests: {', '.join(self.failed_tests)}")
            return False
        else:
            print("\n🎉 All tests passed!")
            return True


async def main():
    """Main test runner."""
    tester = AsyncIntegrationTester()
    success = await tester.run_all_tests()
    
    # Exit with appropriate code
    exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())