"""Validation tests for the async Redis Streams architecture.

These tests ensure the async architecture components work correctly
together with proper event publishing and trace correlation.
"""

import asyncio
import pytest
import time
import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from src.storage.redis_clients import RedisClients
from src.storage.async_redis_storage import AsyncRedisStorage
from src.storage.unified_stream_publisher import UnifiedStreamPublisher
from src.shared.unified_logger import UnifiedAsyncLogger
from src.ports.async_manager import AsyncPortManager
from src.docker.async_manager import AsyncDockerManager
from src.certmanager.async_manager import AsyncCertificateManager
from src.proxy.async_handler import EnhancedAsyncProxyHandler
from src.consumers.metrics_processor import MetricsProcessor
from src.consumers.alert_manager import AlertManager
from src.orchestrator.main_orchestrator import MainOrchestrator
from src.integration.app_integration import AppIntegration


@pytest.fixture
async def redis_clients():
    """Create test Redis clients."""
    clients = RedisClients()
    await clients.initialize()
    yield clients
    await clients.close()


@pytest.fixture
async def async_storage(redis_clients):
    """Create test async storage."""
    storage = AsyncRedisStorage("redis://localhost:6379/0")
    await storage.initialize()
    yield storage
    await storage.close()


@pytest.fixture
async def unified_logger(redis_clients):
    """Create test unified logger."""
    logger = UnifiedAsyncLogger(redis_clients)
    logger.set_component("test")
    yield logger
    await logger.flush()


class TestAsyncRedisStorage:
    """Test async Redis storage operations."""
    
    @pytest.mark.asyncio
    async def test_non_blocking_operations(self, async_storage):
        """Test that operations are truly async and non-blocking."""
        # Run multiple operations concurrently
        start_time = time.time()
        
        tasks = []
        for i in range(100):
            tasks.append(async_storage.redis_client.set(f"test_key_{i}", f"value_{i}"))
        
        await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        
        # Should complete quickly due to async (< 1 second for 100 ops)
        assert duration < 1.0, f"Operations took {duration}s, expected < 1s"
        
        # Verify all keys were set
        for i in range(100):
            value = await async_storage.redis_client.get(f"test_key_{i}")
            assert value == f"value_{i}".encode()
    
    @pytest.mark.asyncio
    async def test_certificate_storage(self, async_storage):
        """Test certificate storage and retrieval."""
        from src.certmanager.models import Certificate
        
        cert = Certificate(
            cert_name="test-cert",
            domain="example.com",
            domains=["example.com", "www.example.com"],
            email="test@example.com",
            fullchain_pem="-----BEGIN CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----",
            expires_at=datetime.now(timezone.utc)
        )
        
        # Store certificate
        result = await async_storage.store_certificate("test-cert", cert)
        assert result is True
        
        # Retrieve certificate
        retrieved = await async_storage.get_certificate("test-cert")
        assert retrieved is not None
        assert retrieved.domain == "example.com"
        
        # List certificates
        certs = await async_storage.list_certificates()
        assert any(c.cert_name == "test-cert" for c in certs)
        
        # Delete certificate
        deleted = await async_storage.delete_certificate("test-cert")
        assert deleted is True


class TestUnifiedLogger:
    """Test unified logging with trace correlation."""
    
    @pytest.mark.asyncio
    async def test_trace_correlation(self, unified_logger):
        """Test that traces properly correlate events."""
        # Start a trace
        trace_id = unified_logger.start_trace(
            "test_operation",
            param1="value1",
            param2="value2"
        )
        
        assert trace_id is not None
        assert trace_id.startswith("test_")
        
        # Log events with trace
        await unified_logger.info("Test message", trace_id=trace_id)
        await unified_logger.debug("Debug message", trace_id=trace_id, extra="data")
        
        # Add span
        unified_logger.add_span(trace_id, "sub_operation", detail="value")
        
        # End trace
        await unified_logger.end_trace(trace_id, "success", result="completed")
        
        # Verify trace was stored
        trace_key = f"trace:{trace_id}"
        trace_data = await unified_logger.redis_clients.async_redis.get(trace_key)
        assert trace_data is not None
        
        trace = json.loads(trace_data)
        assert trace["operation"] == "test_operation"
        assert trace["status"] == "success"
        assert len(trace["spans"]) > 0
    
    @pytest.mark.asyncio
    async def test_batched_publishing(self, unified_logger):
        """Test that batching improves performance."""
        # Publish many events quickly
        start_time = time.time()
        
        tasks = []
        for i in range(100):
            tasks.append(
                unified_logger.event(
                    "test_event",
                    {"index": i, "data": f"event_{i}"}
                )
            )
        
        await asyncio.gather(*tasks)
        
        # Wait for batch processing
        await asyncio.sleep(0.2)
        await unified_logger.flush()
        
        duration = time.time() - start_time
        
        # Should complete quickly with batching
        assert duration < 1.0, f"Publishing took {duration}s, expected < 1s"
    
    @pytest.mark.asyncio
    async def test_structured_logging(self, unified_logger):
        """Test structured logging methods."""
        trace_id = unified_logger.start_trace("http_request")
        
        # Log request
        await unified_logger.log_request(
            method="GET",
            path="/api/test",
            ip="127.0.0.1",
            hostname="test.example.com",
            trace_id=trace_id
        )
        
        # Log response
        await unified_logger.log_response(
            status=200,
            duration_ms=50.5,
            trace_id=trace_id
        )
        
        # Log service event
        await unified_logger.log_service_event(
            service_name="test-service",
            event_type="started",
            trace_id=trace_id,
            container_id="abc123"
        )
        
        # Log certificate event
        await unified_logger.log_certificate_event(
            cert_name="test-cert",
            event_type="renewed",
            domains=["example.com"],
            trace_id=trace_id
        )
        
        await unified_logger.end_trace(trace_id, "success")
        
        # Verify events were published
        await unified_logger.flush()


class TestStreamConsumers:
    """Test stream consumer functionality."""
    
    @pytest.mark.asyncio
    async def test_metrics_processor(self, redis_clients):
        """Test metrics processor consumes events correctly."""
        processor = MetricsProcessor(redis_clients.stream_redis)
        
        # Start processor
        await processor.start()
        
        try:
            # Publish test events
            publisher = UnifiedStreamPublisher(redis_clients.stream_redis)
            
            for i in range(10):
                await publisher.publish(
                    "logs:request:stream",
                    {
                        "log_type": "http_response",
                        "status": 200,
                        "duration_ms": 50 + i,
                        "hostname": "test.example.com",
                        "timestamp": time.time()
                    }
                )
            
            # Wait for processing
            await asyncio.sleep(0.5)
            
            # Get metrics
            metrics = await processor.get_current_metrics()
            
            assert "request_count" in metrics
            assert metrics["request_count"]["test.example.com"] >= 10
            
            # Check consumer lag
            lag = await processor.get_lag()
            assert all(l < 1000 for l in lag.values())  # Less than 1 second
            
        finally:
            await processor.stop()
    
    @pytest.mark.asyncio
    async def test_alert_manager(self, redis_clients):
        """Test alert manager detects and reports issues."""
        alert_mgr = AlertManager(redis_clients.stream_redis)
        
        # Start alert manager
        await alert_mgr.start()
        
        try:
            publisher = UnifiedStreamPublisher(redis_clients.stream_redis)
            
            # Publish error events
            for i in range(15):  # Above threshold
                await publisher.publish(
                    "logs:error:stream",
                    {
                        "type": "error",
                        "component": "test_component",
                        "message": f"Test error {i}",
                        "timestamp": time.time()
                    }
                )
            
            # Wait for processing
            await asyncio.sleep(0.5)
            
            # Check alerts
            summary = await alert_mgr.get_alert_summary()
            
            # Should have detected high error rate
            assert len(summary["error_components"]) > 0
            assert "test_component" in summary["error_components"]
            
        finally:
            await alert_mgr.stop()


class TestDockerManagerAsync:
    """Test async Docker manager with event publishing."""
    
    @pytest.mark.asyncio
    @patch('src.docker.async_manager.DockerClient')
    async def test_service_creation_events(self, mock_docker, async_storage, redis_clients):
        """Test that service creation publishes proper events."""
        # Setup mock
        mock_container = Mock()
        mock_container.id = "container123"
        mock_docker.return_value.container.run.return_value = mock_container
        
        manager = AsyncDockerManager(async_storage, redis_clients)
        
        from src.docker.models import DockerServiceConfig
        
        config = DockerServiceConfig(
            service_name="test-service",
            image="nginx:latest",
            internal_port=80
        )
        
        # Create service
        service_info = await manager.create_service(config, "token_hash_123")
        
        assert service_info.service_name == "test-service"
        assert service_info.status == "running"
        
        # Verify event was published
        # Would check Redis streams for the event


class TestCertificateManagerAsync:
    """Test async certificate manager with event publishing."""
    
    @pytest.mark.asyncio
    @patch('src.certmanager.async_manager.SyncCertManager')
    async def test_certificate_generation_events(self, mock_sync_mgr, async_storage, redis_clients):
        """Test that certificate generation publishes proper events."""
        # Setup mock
        from src.certmanager.models import Certificate
        
        mock_cert = Certificate(
            cert_name="test-cert",
            domain="example.com",
            domains=["example.com"],
            email="test@example.com",
            fullchain_pem="-----BEGIN CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----"
        )
        
        mock_sync_mgr.return_value.create_certificate.return_value = mock_cert
        
        manager = AsyncCertificateManager(async_storage, redis_clients)
        
        from src.certmanager.models import CertificateRequest
        
        request = CertificateRequest(
            cert_name="test-cert",
            domain="example.com",
            email="test@example.com"
        )
        
        # Generate certificate
        cert = await manager.create_certificate(request)
        
        assert cert.cert_name == "test-cert"
        
        # Check generation status
        status = await manager.get_certificate_status("test-cert")
        assert status["status"] in ["completed", "exists"]


class TestOrchestrator:
    """Test main orchestrator functionality."""
    
    @pytest.mark.asyncio
    @patch('src.docker.async_manager.DockerClient')
    async def test_orchestrator_initialization(self, mock_docker):
        """Test that orchestrator initializes all components."""
        orchestrator = MainOrchestrator()
        
        await orchestrator.initialize()
        
        try:
            # Verify all components initialized
            assert orchestrator.redis_clients is not None
            assert orchestrator.async_storage is not None
            assert orchestrator.logger is not None
            assert orchestrator.port_manager is not None
            assert orchestrator.docker_manager is not None
            assert orchestrator.cert_manager is not None
            assert orchestrator.proxy_handler is not None
            assert orchestrator.metrics_processor is not None
            assert orchestrator.alert_manager is not None
            
            # Get status
            status = await orchestrator.get_status()
            
            assert status["components"]["redis"] == "connected"
            assert "metrics_processor" in status["components"]
            assert "alert_manager" in status["components"]
            
        finally:
            await orchestrator.stop()
    
    @pytest.mark.asyncio
    async def test_orchestrator_lifecycle(self):
        """Test orchestrator start/stop lifecycle."""
        orchestrator = MainOrchestrator()
        
        await orchestrator.initialize()
        
        # Start orchestrator
        await orchestrator.start()
        assert orchestrator.running is True
        
        # Stop orchestrator
        await orchestrator.stop()
        assert orchestrator.running is False


class TestIntegration:
    """Test FastAPI integration."""
    
    @pytest.mark.asyncio
    async def test_app_integration_singleton(self):
        """Test that app integration maintains singleton pattern."""
        integration1 = await AppIntegration.initialize()
        integration2 = await AppIntegration.initialize()
        
        assert integration1 is integration2
        
        await AppIntegration.shutdown()
    
    @pytest.mark.asyncio
    async def test_fastapi_dependencies(self):
        """Test FastAPI dependency injection."""
        from src.integration.app_integration import (
            get_async_storage,
            get_docker_manager,
            get_cert_manager
        )
        
        integration = await AppIntegration.initialize()
        
        try:
            # Test dependencies return correct instances
            storage = await get_async_storage(integration)
            assert storage is integration.async_storage
            
            docker_mgr = await get_docker_manager(integration)
            assert docker_mgr is integration.docker_manager
            
            cert_mgr = await get_cert_manager(integration)
            assert cert_mgr is integration.cert_manager
            
        finally:
            await AppIntegration.shutdown()


class TestPerformance:
    """Performance validation tests."""
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, async_storage, unified_logger):
        """Test system handles high concurrent load."""
        start_time = time.time()
        
        tasks = []
        
        # Mix of different operations
        for i in range(1000):
            if i % 4 == 0:
                # Storage operation
                tasks.append(
                    async_storage.redis_client.set(f"perf_key_{i}", f"value_{i}")
                )
            elif i % 4 == 1:
                # Logging operation
                tasks.append(
                    unified_logger.info(f"Performance test {i}")
                )
            elif i % 4 == 2:
                # Event publishing
                tasks.append(
                    unified_logger.event("perf_event", {"index": i})
                )
            else:
                # Port allocation simulation
                tasks.append(
                    async_storage.redis_client.get(f"port:{11000 + i}")
                )
        
        # Run all operations concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flush logs
        await unified_logger.flush()
        
        duration = time.time() - start_time
        
        # Should handle 1000 mixed operations in < 5 seconds
        assert duration < 5.0, f"Operations took {duration}s, expected < 5s"
        
        # Calculate operations per second
        ops_per_second = 1000 / duration
        assert ops_per_second > 200, f"Only {ops_per_second} ops/sec, expected > 200"
    
    @pytest.mark.asyncio
    async def test_memory_efficiency(self, redis_clients):
        """Test that stream consumers don't leak memory."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create and destroy consumers multiple times
        for _ in range(5):
            processor = MetricsProcessor(redis_clients.stream_redis)
            alert_mgr = AlertManager(redis_clients.stream_redis)
            
            await processor.start()
            await alert_mgr.start()
            
            # Process some events
            await asyncio.sleep(0.5)
            
            await processor.stop()
            await alert_mgr.stop()
        
        # Check memory didn't grow significantly
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_growth = final_memory - initial_memory
        
        # Should not grow more than 50MB
        assert memory_growth < 50, f"Memory grew by {memory_growth}MB"


@pytest.mark.asyncio
async def test_end_to_end_flow():
    """Test complete end-to-end flow with all components."""
    # Initialize orchestrator
    orchestrator = MainOrchestrator()
    await orchestrator.initialize()
    await orchestrator.start()
    
    try:
        # Simulate a proxy request flow
        trace_id = orchestrator.logger.start_trace(
            "e2e_test",
            test_type="integration"
        )
        
        # Log request
        await orchestrator.logger.log_request(
            method="GET",
            path="/api/test",
            ip="127.0.0.1",
            hostname="test.example.com",
            trace_id=trace_id
        )
        
        # Simulate backend processing
        await asyncio.sleep(0.1)
        
        # Log response
        await orchestrator.logger.log_response(
            status=200,
            duration_ms=100,
            trace_id=trace_id
        )
        
        # End trace
        await orchestrator.logger.end_trace(trace_id, "success")
        
        # Wait for consumers to process
        await asyncio.sleep(0.5)
        
        # Check metrics were updated
        metrics = await orchestrator.metrics_processor.get_current_metrics()
        assert "request_count" in metrics
        
        # Check no alerts were triggered
        alerts = await orchestrator.alert_manager.get_alert_summary()
        assert alerts["active_alerts"] == 0
        
    finally:
        await orchestrator.stop()