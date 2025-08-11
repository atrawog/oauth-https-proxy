# Router Refactoring Plan

## Goals
1. **Maintainability**: Files under 300 lines
2. **Single Responsibility**: Each file has one clear purpose
3. **Async-First**: New structure optimized for async patterns
4. **Reusability**: Shared logic extracted to utilities

## Proposed Structure

### 1. Services Module (868 → ~200 lines each)
```
src/api/routers/v1/services/
├── __init__.py           # Router aggregation
├── docker.py             # Docker service endpoints (~250 lines)
├── external.py           # External service registration (~150 lines)
├── ports.py              # Port management endpoints (~200 lines)
├── proxy_integration.py  # Service proxy creation (~100 lines)
└── utils.py              # Shared utilities (~100 lines)
```

### 2. Proxies Module (709 → ~150 lines each)
```
src/api/routers/v1/proxies/
├── __init__.py          # Router aggregation
├── core.py              # Basic CRUD operations (~200 lines)
├── auth.py              # Authentication configuration (~150 lines)
├── routes.py            # Route management (~150 lines)
├── resources.py         # MCP resource configuration (~100 lines)
└── certificates.py      # Certificate integration (~100 lines)
```

### 3. OAuth Module (584 + 152 → ~150 lines each)
```
src/api/routers/v1/oauth/
├── __init__.py          # Router aggregation
├── clients.py           # Client management (~150 lines)
├── sessions.py          # Session management (~150 lines)
├── tokens.py            # Token operations (~150 lines)
├── metrics.py           # Metrics and health (~100 lines)
└── admin.py             # Admin operations (~150 lines)
```

### 4. Logs Module (562 → ~150 lines each)
```
src/api/routers/v1/logs/
├── __init__.py          # Router aggregation
├── query.py             # Log queries (~200 lines)
├── analytics.py         # Analytics endpoints (~150 lines)
├── streaming.py         # Real-time streaming (~100 lines)
└── utils.py             # Query builders (~100 lines)
```

### 5. Tokens Module (490 → ~150 lines each)
```
src/api/routers/v1/tokens/
├── __init__.py          # Router aggregation
├── crud.py              # Basic CRUD operations (~200 lines)
├── reveal.py            # Token reveal logic (~100 lines)
├── email.py             # Email management (~100 lines)
└── utils.py             # Token utilities (~100 lines)
```

## Migration Strategy

### Phase 1: Create Module Structure
1. Create directory structure
2. Split files by functionality
3. Create aggregation routers

### Phase 2: Async Migration
1. Migrate each small module to async
2. Add Request parameter systematically
3. Use async storage throughout

### Phase 3: Optimization
1. Extract common patterns
2. Create async utilities
3. Add proper error handling

## Benefits
- **Easier Testing**: Can test individual concerns
- **Parallel Development**: Multiple modules can be worked on simultaneously
- **Better Documentation**: Each module has clear purpose
- **Faster Debugging**: Issues isolated to specific modules
- **Cleaner Imports**: More organized dependency tree

## Implementation Order
1. Start with proxies (already partially migrated)
2. Move to services (largest file)
3. Continue with oauth
4. Then logs
5. Finally tokens