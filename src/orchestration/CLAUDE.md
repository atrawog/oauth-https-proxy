# Workflow Orchestrator Documentation

## Overview

The Workflow Orchestrator provides zero-restart, event-driven lifecycle management for proxy instances. All proxy instances are created dynamically via events - NO startup creation!

## Architecture

```
API/Certificate Manager → Redis Stream Event → Workflow Orchestrator → Create/Update/Delete Instance
                                ↓
                        Consumer Group (workflow-group)
                                ↓
                        Exactly-once processing
```

## Event-Driven Instance Lifecycle

The system uses Redis Streams for reliable event processing with exactly-once semantics.

## Redis Streams Configuration

- **Stream**: `events:workflow` - Main event stream for instance lifecycle
- **Consumer Group**: `workflow-group` - Ensures exactly-once processing
- **Events**:
  - `proxy_created` - New proxy needs instance creation
  - `certificate_ready` - Certificate available, upgrade to HTTPS
  - `proxy_updated` - Proxy configuration changed
  - `proxy_deleted` - Proxy removed, cleanup instance

## Event Schema

```json
{
  "event_type": "proxy_created",
  "hostname": "api.example.com",
  "data": {
    "enable_http": true,
    "enable_https": false,
    "cert_name": null
  },
  "timestamp": "2024-01-15T10:00:00Z"
}
```

## Workflow Orchestrator Flow

### 1. Proxy Creation
- API creates proxy → publishes `proxy_created` event
- Orchestrator creates HTTP-only instance immediately
- Proxy works instantly without restart

### 2. Certificate Ready
- Certificate manager obtains cert → publishes `certificate_ready` event
- Orchestrator upgrades instance to HTTPS
- Zero downtime transition

### 3. Proxy Updates
- Configuration changes → publishes `proxy_updated` event
- Orchestrator updates instance in-place
- No restart required

### 4. Proxy Deletion
- API deletes proxy → publishes `proxy_deleted` event
- Orchestrator cleanly shuts down instance
- Resources properly released

## Key Benefits

- **Zero-Restart**: Proxies work immediately upon creation
- **Reliability**: Redis Streams with consumer groups ensure no events are lost
- **Idempotency**: Exactly-once processing prevents duplicate instances
- **Clean Separation**: API doesn't know about instances, orchestrator doesn't know about API
- **Scalability**: Can run multiple orchestrator consumers for high availability

## Consumer Implementation

```python
class WorkflowOrchestrator:
    async def consume_events(self):
        """Main consumer loop"""
        while True:
            # Read from stream with consumer group
            events = await redis.xreadgroup(
                group="workflow-group",
                consumer="orchestrator-1",
                streams={"events:workflow": ">"},
                block=1000
            )
            
            for event in events:
                await self.process_event(event)
                await redis.xack("events:workflow", "workflow-group", event.id)
```

## Event Processing

### Proxy Created Event
```python
async def handle_proxy_created(event_data):
    hostname = event_data["hostname"]
    enable_http = event_data["enable_http"]
    enable_https = event_data["enable_https"]
    
    # Create instance
    instance = await create_proxy_instance(hostname)
    
    # Configure HTTP
    if enable_http:
        await instance.enable_http()
    
    # Configure HTTPS if certificate exists
    if enable_https and await has_certificate(hostname):
        await instance.enable_https()
```

### Certificate Ready Event
```python
async def handle_certificate_ready(event_data):
    hostname = event_data["hostname"]
    cert_name = event_data["cert_name"]
    
    # Get existing instance
    instance = await get_instance(hostname)
    
    # Upgrade to HTTPS
    ssl_context = await load_ssl_context(cert_name)
    await instance.upgrade_to_https(ssl_context)
```

## State Management

### Workflow State Tracking
```
workflow:state:{hostname}   # Current state of workflow for each hostname
workflow:pending            # Set of pending workflow tasks
workflow:consumer:info      # Consumer group metadata
```

### State Machine
```
PENDING → CREATING → ACTIVE → UPDATING → ACTIVE
                           ↓
                       DELETING → DELETED
```

## Error Handling

### Retry Logic
```python
async def process_with_retry(event, max_retries=3):
    for attempt in range(max_retries):
        try:
            await process_event(event)
            return True
        except Exception as e:
            if attempt == max_retries - 1:
                await dead_letter_queue(event, str(e))
            await asyncio.sleep(2 ** attempt)  # Exponential backoff
```

### Dead Letter Queue
Failed events after max retries:
```
events:workflow:dlq         # Dead letter queue stream
workflow:failures:{id}      # Failure details
```

## Monitoring

### Consumer Metrics
- Event processing rate
- Lag (pending events)
- Error rate
- Processing time

### Health Checks
```python
async def health_check():
    return {
        "consumer_active": is_consuming,
        "pending_events": await get_pending_count(),
        "last_event_time": last_processed_time,
        "error_count": error_counter
    }
```

## Scaling

### Multiple Consumers
```yaml
# docker-compose.yml
orchestrator1:
  environment:
    CONSUMER_NAME: orchestrator-1
    
orchestrator2:
  environment:
    CONSUMER_NAME: orchestrator-2
```

### Load Distribution
Redis Streams automatically distributes events among consumers in the same group.

## Integration Points

### Event Publishers
- **API**: Publishes proxy CRUD events
- **Certificate Manager**: Publishes certificate events
- **Route Manager**: Publishes route change events

### Instance Manager
- Creates/updates/deletes proxy instances
- Manages SSL contexts
- Handles graceful shutdowns

## Best Practices

1. **Idempotent Operations**: Ensure event processing is idempotent
2. **Atomic State Updates**: Use Redis transactions for state changes
3. **Event Ordering**: Process events in order per hostname
4. **Graceful Shutdown**: Complete current event before stopping
5. **Monitoring**: Track lag and error rates

## Troubleshooting

### Common Issues

1. **Events Not Processing**: Check consumer group exists
2. **Duplicate Instances**: Verify idempotency logic
3. **Memory Leaks**: Check for unclosed resources
4. **High Lag**: Scale up consumers or optimize processing

### Debug Commands

```bash
# Check pending events
redis-cli XPENDING events:workflow workflow-group

# View consumer info
redis-cli XINFO CONSUMERS events:workflow workflow-group

# Read event stream
redis-cli XRANGE events:workflow - +

# Check workflow state
redis-cli GET workflow:state:hostname
```

## Event Publishing

### From API
```python
async def create_proxy(hostname: str, config: dict):
    # Save proxy config
    await redis.set(f"proxy:{hostname}", json.dumps(config))
    
    # Publish event
    await redis.xadd("events:workflow", {
        "event_type": "proxy_created",
        "hostname": hostname,
        "data": json.dumps(config)
    })
```

### From Certificate Manager
```python
async def certificate_ready(cert_name: str, hostname: str):
    await redis.xadd("events:workflow", {
        "event_type": "certificate_ready",
        "hostname": hostname,
        "cert_name": cert_name
    })
```

## Related Documentation

- [Storage](../storage/CLAUDE.md) - Redis Streams details
- [Dispatcher](../dispatcher/CLAUDE.md) - Instance management
- [Proxy Manager](../proxy/CLAUDE.md) - Proxy lifecycle
- [Certificate Manager](../certmanager/CLAUDE.md) - Certificate events