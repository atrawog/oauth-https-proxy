# Async Redis Streams Architecture Migration Guide

## Overview

This guide explains how to migrate the existing codebase to the new unified async Redis Streams architecture. The new architecture provides:

- **True async operations** - No more event loop blocking
- **Unified logging and events** - Single interface for all telemetry
- **Stream-based processing** - Real-time event processing with consumer groups
- **Trace correlation** - End-to-end request tracing

## Architecture Components

### 1. Core Infrastructure (Phase 1)

#### AsyncRedisStorage (`src/storage/async_redis_storage.py`)
Replaces the synchronous `RedisStorage` with fully async operations.

**Migration Steps:**
```python
# Old (blocking)
from src.storage import RedisStorage
storage = RedisStorage(redis_url)
cert = storage.get_certificate("cert-name")  # Blocks!

# New (non-blocking)
from src.storage.async_redis_storage import AsyncRedisStorage
storage = AsyncRedisStorage(redis_url)
await storage.initialize()
cert = await storage.get_certificate("cert-name")  # Non-blocking!
```

#### AsyncPortManager (`src/ports/async_manager.py`)
Fixes false async methods that were calling sync Redis.

**Migration Steps:**
```python
# Old
from src.ports import PortManager
port_mgr = PortManager(storage)
port = await port_mgr.allocate_port()  # False async!

# New
from src.ports.async_manager import AsyncPortManager
port_mgr = AsyncPortManager(async_storage)
port = await port_mgr.allocate_port()  # True async!
```

#### RedisClients (`src/storage/redis_clients.py`)
Manages multiple Redis connections for different purposes.

**Usage:**
```python
from src.storage.redis_clients import RedisClients, initialize_redis_clients

# Initialize once at startup
redis_clients = await initialize_redis_clients()

# Use appropriate client
await redis_clients.async_redis.get("key")  # For storage
await redis_clients.stream_redis.xadd(...)  # For streams
# redis_clients.sync_redis for legacy ops in executors
```

### 2. Unified Logging & Events (Phase 2)

#### UnifiedStreamPublisher (`src/storage/unified_stream_publisher.py`)
Low-level publisher for events and logs.

#### UnifiedAsyncLogger (`src/shared/unified_logger.py`)
High-level interface for logging with trace correlation.

**Migration Example - ProxyHandler:**
```python
# Old
logger.info(f"Proxy request from {ip}")
logger.error(f"Backend failed: {error}")

# New
from src.shared.unified_logger import UnifiedAsyncLogger

class EnhancedProxyHandler:
    def __init__(self, redis_clients):
        self.logger = UnifiedAsyncLogger(redis_clients)
        self.logger.set_component("proxy_handler")
    
    async def handle_request(self, request):
        # Start trace
        trace_id = self.logger.start_trace("proxy_request", 
                                          hostname=hostname)
        
        try:
            # Log request
            await self.logger.log_request(
                method=request.method,
                path=request.path,
                ip=client_ip,
                hostname=hostname,
                trace_id=trace_id
            )
            
            # Process...
            response = await self._proxy_to_backend(request)
            
            # Log response
            await self.logger.log_response(
                status=response.status,
                duration_ms=duration,
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "success")
            
        except Exception as e:
            await self.logger.log_error_exception(e, 
                                                 {"url": request.url},
                                                 trace_id=trace_id)
            await self.logger.end_trace(trace_id, "error")
            raise
```

### 3. Stream Consumers (Phase 4)

#### MetricsProcessor (`src/consumers/metrics_processor.py`)
Generates real-time metrics from event streams.

#### AlertManager (`src/consumers/alert_manager.py`)
Monitors for anomalies and sends alerts.

**Starting Consumers:**
```python
# In main.py or orchestrator
from src.consumers import MetricsProcessor, AlertManager

async def start_consumers(redis_clients):
    # Create consumers
    metrics = MetricsProcessor(redis_clients.stream_redis)
    alerts = AlertManager(redis_clients.stream_redis)
    
    # Start processing
    await metrics.start()
    await alerts.start()
    
    return metrics, alerts

# On shutdown
async def stop_consumers(metrics, alerts):
    await metrics.stop()
    await alerts.stop()
```

## Component-Specific Migration

### DockerManager Migration

```python
# src/docker/manager.py

from src.shared.unified_logger import UnifiedAsyncLogger

class DockerManager:
    def __init__(self, storage: AsyncRedisStorage, redis_clients):
        self.storage = storage
        self.logger = UnifiedAsyncLogger(redis_clients)
        self.logger.set_component("docker_manager")
    
    async def create_service(self, config):
        trace_id = self.logger.start_trace("service_create",
                                          service_name=config.service_name)
        
        try:
            # Log start
            await self.logger.info(
                f"Creating service {config.service_name}",
                trace_id=trace_id
            )
            
            # Run sync Docker operation in executor
            container = await loop.run_in_executor(
                executor,
                self._sync_create_container,
                config
            )
            
            # Publish event for other components
            await self.logger.log_service_event(
                service_name=config.service_name,
                event_type="created",
                trace_id=trace_id,
                container_id=container.id,
                ports=config.port_configs
            )
            
            await self.logger.end_trace(trace_id, "success")
            return container
            
        except Exception as e:
            await self.logger.log_service_event(
                service_name=config.service_name,
                event_type="failed",
                trace_id=trace_id,
                error=str(e)
            )
            await self.logger.end_trace(trace_id, "error")
            raise
```

### CertificateManager Migration

```python
# src/certmanager/async_acme.py

async def generate_certificate_async(manager, request):
    trace_id = logger.start_trace("cert_generation",
                                 cert_name=request.cert_name,
                                 domains=request.domains)
    
    try:
        # Publish start event
        await logger.log_certificate_event(
            cert_name=request.cert_name,
            event_type="generation_started",
            domains=request.domains,
            trace_id=trace_id
        )
        
        # Run sync ACME in executor
        cert = await loop.run_in_executor(
            executor,
            manager._sync_generate_cert,
            request
        )
        
        # Store with async storage
        await async_storage.store_certificate(request.cert_name, cert)
        
        # Publish completion event
        await logger.log_certificate_event(
            cert_name=cert.cert_name,
            event_type="ready",
            domains=cert.domains,
            trace_id=trace_id,
            expires_at=cert.expires_at.isoformat()
        )
        
        await logger.end_trace(trace_id, "success")
        return cert
        
    except Exception as e:
        await logger.log_certificate_event(
            cert_name=request.cert_name,
            event_type="failed",
            domains=request.domains,
            trace_id=trace_id,
            error=str(e)
        )
        await logger.end_trace(trace_id, "error")
        raise
```

### Main Application Startup

```python
# src/main.py

import asyncio
from src.storage.redis_clients import RedisClients
from src.storage.async_redis_storage import AsyncRedisStorage
from src.shared.unified_logger import UnifiedAsyncLogger
from src.consumers import MetricsProcessor, AlertManager

async def startup():
    # Initialize Redis clients
    redis_clients = RedisClients()
    await redis_clients.initialize()
    
    # Initialize async storage
    async_storage = AsyncRedisStorage(redis_clients.redis_url)
    await async_storage.initialize()
    
    # Initialize unified logger
    logger = UnifiedAsyncLogger(redis_clients)
    
    # Start consumers
    metrics = MetricsProcessor(redis_clients.stream_redis)
    alerts = AlertManager(redis_clients.stream_redis)
    
    await metrics.start()
    await alerts.start()
    
    # Store for use in app
    app.state.redis_clients = redis_clients
    app.state.async_storage = async_storage
    app.state.logger = logger
    app.state.metrics = metrics
    app.state.alerts = alerts

async def shutdown():
    # Stop consumers
    await app.state.metrics.stop()
    await app.state.alerts.stop()
    
    # Flush logs
    await app.state.logger.flush()
    
    # Close connections
    await app.state.async_storage.close()
    await app.state.redis_clients.close()
```

## Migration Checklist

### Phase 1: Infrastructure
- [ ] Deploy new async modules alongside existing code
- [ ] Initialize RedisClients at startup
- [ ] Replace RedisStorage with AsyncRedisStorage in new code
- [ ] Update PortManager to AsyncPortManager

### Phase 2: Logging
- [ ] Initialize UnifiedAsyncLogger
- [ ] Add trace IDs to request handlers
- [ ] Replace logger calls with unified logger
- [ ] Add component names to all loggers

### Phase 3: Event Publishing
- [ ] Add event publishing to DockerManager
- [ ] Add event publishing to CertificateManager
- [ ] Add event publishing to ProxyHandler
- [ ] Add event publishing to route changes

### Phase 4: Consumers
- [ ] Deploy MetricsProcessor
- [ ] Deploy AlertManager
- [ ] Configure alert thresholds
- [ ] Set up alert destinations

### Phase 5: Validation
- [ ] Verify no blocking operations in async contexts
- [ ] Check consumer lag < 1 second
- [ ] Verify trace correlation working
- [ ] Monitor memory usage

## Performance Expectations

### Before Migration
- Redis operations: 100-500 ops/sec (blocking)
- Request latency: 50-200ms (with spikes)
- CPU usage: 40-60% (waiting on I/O)

### After Migration
- Redis operations: 5,000-10,000 ops/sec (async)
- Request latency: 10-50ms (consistent)
- CPU usage: 20-30% (efficient async)
- Consumer lag: < 1 second
- Event processing: < 100ms

## Rollback Plan

The new architecture is designed for parallel deployment:

1. **Deploy new code alongside old** - No immediate changes required
2. **Dual-write period** - Write to both old and new systems
3. **Gradual migration** - Move components one at a time
4. **Monitor and validate** - Check metrics and logs
5. **Complete cutover** - Remove old code when confident

## Common Issues & Solutions

### Issue: "Redis not initialized"
**Solution:** Ensure `await redis_clients.initialize()` is called at startup

### Issue: "Cannot await sync function"
**Solution:** The function needs to be converted to async or run in executor

### Issue: "Consumer lag increasing"
**Solution:** Add more consumer instances or optimize handlers

### Issue: "Traces not correlating"
**Solution:** Ensure trace_id is passed through all async calls

## Monitoring

### Key Metrics to Watch
```python
# Consumer lag
lag = await consumer.get_lag()
assert all(l < 1000 for l in lag.values())  # < 1 second

# Processing rate
stats = await metrics.get_stats()
assert stats["messages_processed"] > 100  # per minute

# Error rate
alerts_summary = await alerts.get_alert_summary()
assert alerts_summary["hourly_counts"].get("CRITICAL", 0) == 0
```

### Redis Memory Usage
```bash
# Check memory usage
redis-cli INFO memory

# Check stream lengths
redis-cli XLEN logs:all:stream
redis-cli XLEN events:all:stream

# Check consumer groups
redis-cli XINFO GROUPS logs:request:stream
```

## Support

For questions or issues during migration:
1. Check this guide first
2. Review the example implementations
3. Check logs in Redis Streams
4. Monitor consumer statistics

The new architecture is designed to be deployed incrementally with minimal risk. Start with non-critical components and gradually migrate the entire system.