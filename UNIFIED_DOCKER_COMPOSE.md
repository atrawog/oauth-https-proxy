# Unified Docker Compose Configuration

## Summary

Successfully merged `docker-compose.yml` and `docker-compose.test.yml` into a single unified configuration that supports both deployment and testing scenarios.

## Key Changes

### 1. **Unified docker-compose.yml**
- Kept all production services (redis, acme-certmanager, fetcher-mcp)
- Added test-runner service with `profiles: ["test"]` 
- Mounted source code volumes for development hot-reloading
- Made LOG_LEVEL configurable via environment variable

### 2. **Source Code Mounting**
Added volume mounts to acme-certmanager for development:
```yaml
volumes:
  - ./logs:/app/logs
  - ./acme_certmanager:/app/acme_certmanager  # Hot reload
  - ./scripts:/app/scripts                    # Hot reload
  - ./tests:/app/tests                        # Hot reload
```

### 3. **Test Runner Profile**
Test runner only runs when explicitly requested:
```yaml
test-runner:
  profiles: ["test"]  # Only runs with --profile test
  command: pixi run pytest tests/ -v --tb=short
```

### 4. **Environment Variables**
- `LOG_LEVEL=${LOG_LEVEL:-INFO}` - Defaults to INFO, can override
- `PYTHONPATH=/app` - Ensures proper Python imports

### 5. **Justfile Update**
Changed test-integration command:
```bash
# Old
docker-compose -f docker-compose.yml -f docker-compose.test.yml run --rm test-runner

# New
docker-compose --profile test run --rm test-runner
```

## Usage

### Production/Development
```bash
just up              # Start all services
just down            # Stop all services
just logs            # View logs
just restart <service>  # Restart specific service
```

### Testing
```bash
just test-integration   # Run tests in Docker
LOG_LEVEL=DEBUG just up # Start with debug logging
```

### Benefits
1. **Single configuration file** - Easier to maintain
2. **Hot reloading** - Code changes reflected immediately
3. **Flexible logging** - Adjust verbosity as needed
4. **Clean separation** - Test runner isolated with profile
5. **No port conflicts** - Same ports for all scenarios

## Fetcher MCP Status

The fetcher-mcp service is running but requires proper MCP client configuration:
- Direct HTTP requests to `/mcp` endpoint fail due to session requirements
- The service expects SSE (Server-Sent Events) connections
- OAuth is not configured on the fetcher service
- Use mcp-streamablehttp-client for proper protocol handling

## Next Steps

1. Configure proper MCP client for fetcher service
2. Set up OAuth if needed for production
3. Document MCP protocol requirements
4. Add health checks for all services