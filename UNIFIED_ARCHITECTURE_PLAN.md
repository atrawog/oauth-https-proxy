# Unified Architecture Implementation Plan

## Overview

Transform the architecture from FastAPI-centric to Dispatcher-centric, where UnifiedDispatcher owns ports 80/443 and manages ALL instances including FastAPI.

## Current Problem

```
Port 80/443 → FastAPI (owns these)
     ↓
Port 80/443 → UnifiedDispatcher (also wants these!)
     ↓
CONFLICT & RACE CONDITIONS
```

## Target Architecture

```
Port 80/443 → UnifiedDispatcher (THE server)
     ↓
     ├→ localhost:9000 → FastAPI instance (API/GUI)
     ├→ localhost:9001 → fetcher.example.com instance  
     └→ localhost:9002+ → Other domain instances
```

## Implementation Steps

### Phase 1: Create New Entry Point
1. Create `main_dispatcher.py` as the new entry point
2. UnifiedDispatcher starts first and owns ports 80/443
3. Creates FastAPI as a child instance on port 9000
4. No more port conflicts!

### Phase 2: Refactor FastAPI Startup
1. Remove port binding from FastAPI server.py
2. FastAPI becomes a pure ASGI app without server responsibilities
3. UnifiedDispatcher creates DomainInstance for FastAPI
4. FastAPI instance registered as 'localhost' and 'api'

### Phase 3: Fix Dynamic Instance Management
1. unified_server_instance available from startup
2. Proxy creation triggers immediate instance creation
3. Certificate completion triggers HTTPS enablement
4. No manual restarts required!

### Phase 4: Update Docker Configuration
1. Change entrypoint to main_dispatcher.py
2. Ensure proper startup order
3. Health checks verify dispatcher is routing

## Key Code Changes

### 1. New main_dispatcher.py
```python
async def main():
    # Initialize storage and manager
    manager = CertificateManager()
    https_server = HTTPSServer(manager)
    
    # Create FastAPI app (without server)
    from .server import create_app
    app = create_app(manager, https_server)
    
    # Create and run UnifiedDispatcher
    dispatcher = UnifiedMultiInstanceServer(
        https_server_instance=https_server,
        app=app,
        host='0.0.0.0'
    )
    
    # This now works because dispatcher exists!
    await dispatcher.run()
```

### 2. Modify server.py
```python
def create_app(manager, https_server):
    """Create FastAPI app without server binding"""
    app = FastAPI(lifespan=lifespan)
    # ... configure routes ...
    return app

# Remove if __name__ == "__main__" block
```

### 3. Update UnifiedDispatcher
- Remove the problematic `serve_forever()` calls
- Implement proper async server management
- Ensure FastAPI instance is created first

## Testing Plan

1. Start services with new architecture
2. Verify FastAPI accessible via localhost
3. Test proxy creation with immediate HTTPS
4. Verify fetcher-mcp integration works
5. Test dynamic instance add/remove

## Benefits

- **No Port Conflicts**: Single owner of 80/443
- **No Race Conditions**: Dispatcher exists before API
- **Dynamic Management**: Instant instance creation
- **Clean Architecture**: Each component has clear role
- **Simplified Debugging**: Single routing layer

## Migration Path

1. Implement new architecture in parallel
2. Test thoroughly with staging certificates  
3. Switch Docker entrypoint when ready
4. Remove old startup code

## Success Criteria

- [ ] UnifiedDispatcher starts first
- [ ] FastAPI runs as child instance
- [ ] No port binding conflicts
- [ ] Dynamic proxy creation works immediately
- [ ] HTTPS enabled without restart
- [ ] All existing functionality preserved