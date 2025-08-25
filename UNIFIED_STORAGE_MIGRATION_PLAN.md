# UnifiedStorage Migration Plan - Full Implementation

## Current State Analysis

### ✅ Already Implemented
1. **Core UnifiedStorage class** (`src/storage/unified_storage.py`)
   - Smart sync/async detection via asgiref
   - Auto-initialization on first use
   - Proper async_to_sync/sync_to_async wrapping

2. **Dependencies installed**
   - asgiref >=3.9.1 in pixi.toml

3. **Compatibility shims** (`src/storage/__init__.py`)
   - RedisStorage → UnifiedStorage wrapper
   - AsyncRedisStorage → UnifiedStorage wrapper

4. **Partial migration**
   - redis_storage.py redirects to UnifiedStorage

### ❌ Critical Issues to Fix

1. **Dual Storage Instance Problem**
   - `main.py` creates RedisStorage (UnifiedStorage) instance
   - `async_init.py` creates separate AsyncRedisStorage instance
   - These don't share state → defeats unified architecture purpose
   - OAuth bug likely persists due to split initialization

2. **Direct Import Problem**  
   - 15+ files still import `from ..storage.async_redis_storage import AsyncRedisStorage`
   - Bypasses UnifiedStorage completely
   - No benefit from unified architecture

3. **Incomplete Migration**
   - async_redis_storage.py still exists as standalone implementation
   - Should be internal to UnifiedStorage, not directly accessible

## Implementation Tasks

### Phase 1: Fix Storage Instance Sharing (CRITICAL)

#### Task 1.1: Update async_init.py to use shared storage
```python
# src/api/async_init.py - MODIFY lines 55-58
# REMOVE:
# self.async_storage = AsyncRedisStorage(redis_url)
# await self.async_storage.initialize()

# ADD:
from ..storage import UnifiedStorage
# Get the already-initialized storage from main.py
self.async_storage = storage_instance  # Pass from main.py
```

#### Task 1.2: Pass storage instance from main.py
```python
# src/main.py - MODIFY line 39
# Change from:
async_components = await init_async_components(redis_url)
# To:
async_components = await init_async_components(redis_url, storage)
```

#### Task 1.3: Update init_async_components signature
```python
# src/api/async_init.py - MODIFY function signature
async def init_async_components(redis_url: str, storage: UnifiedStorage) -> AsyncComponents:
    # ... 
    await _async_components.initialize(redis_url, storage)
```

### Phase 2: Update All Direct Imports

#### Task 2.1: Update MCP components (4 files)
- `src/api/routers/mcp/mcp.py`
- `src/api/routers/mcp/event_publisher.py`
- `src/api/routers/mcp/session_manager.py`
- `src/api/routers/mcp/mcp_server.py`

Change all:
```python
from ....storage.async_redis_storage import AsyncRedisStorage
```
To:
```python
from ....storage import UnifiedStorage
```

#### Task 2.2: Update proxy components (2 files)
- `src/proxy/unified_handler.py`
- `src/proxy/app.py`

#### Task 2.3: Update docker managers (2 files)
- `src/docker/manager.py` 
- `src/docker/async_manager.py`

#### Task 2.4: Update other components (5 files)
- `src/integration/app_integration.py`
- `src/orchestrator/main_orchestrator.py`
- `src/certmanager/async_manager.py`
- `src/ports/async_manager.py`
- `src/ports/manager.py`

#### Task 2.5: Update OAuth status
- `src/api/routers/oauth/oauth_status.py`

### Phase 3: Prevent Direct Access to AsyncRedisStorage

#### Task 3.1: Move async_redis_storage.py to private module
```bash
# Rename to indicate it's internal-only
mv src/storage/async_redis_storage.py src/storage/_async_redis_storage.py
```

#### Task 3.2: Update UnifiedStorage import
```python
# src/storage/unified_storage.py - line 79
# Change from:
from .async_redis_storage import AsyncRedisStorage
# To:
from ._async_redis_storage import AsyncRedisStorage
```

#### Task 3.3: Create deprecation wrapper (temporary)
```python
# src/storage/async_redis_storage.py - NEW FILE
"""DEPRECATED: Use UnifiedStorage instead.

This module exists only for backward compatibility during migration.
Direct use of AsyncRedisStorage is deprecated.
"""

import warnings
from .unified_storage import UnifiedStorage

class AsyncRedisStorage(UnifiedStorage):
    """DEPRECATED: Use UnifiedStorage instead."""
    
    def __init__(self, redis_url: str):
        warnings.warn(
            "Direct use of AsyncRedisStorage is deprecated. Use UnifiedStorage instead.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(redis_url)

# For compatibility
__all__ = ['AsyncRedisStorage']
```

### Phase 4: Testing & Validation

#### Task 4.1: Create unified storage test
```python
# tests/test_unified_storage.py
import pytest
import asyncio
from src.storage import UnifiedStorage

def test_single_instance_sharing():
    """Verify storage instance is properly shared."""
    storage1 = UnifiedStorage("redis://localhost:6379")
    storage1.initialize()
    
    # In main.py context
    storage1.set("test_key", "test_value")
    
    # Simulate async_init getting same instance
    storage2 = storage1  # Should be same instance
    assert storage2.get("test_key") == "test_value"
    
@pytest.mark.asyncio
async def test_oauth_initialization():
    """Verify OAuth exclusion paths are set."""
    storage = UnifiedStorage("redis://localhost:6379")
    await storage.initialize_async()
    
    # Check localhost proxy has auth_excluded_paths
    proxy = await storage.get_proxy_target("localhost")
    assert proxy is not None
    assert proxy.auth_excluded_paths is not None
    assert "/token" in proxy.auth_excluded_paths
```

#### Task 4.2: Integration testing
```bash
# Start system and verify no dual storage warnings
just up
just logs-follow | grep "storage"

# Test OAuth flow works (critical bug fix verification)
just oauth-login
just oauth-refresh  # Should work without circular dependency

# Verify single storage instance
just shell
python -c "
from src.storage import UnifiedStorage
s = UnifiedStorage('redis://localhost:6379')
s.initialize()
# Should see only ONE 'UnifiedStorage initialized' log message
"
```

### Phase 5: Documentation Updates

#### Task 5.1: Update storage documentation
- Add migration notes to `src/storage/CLAUDE.md`
- Document UnifiedStorage as the only supported interface
- Mark AsyncRedisStorage/RedisStorage as deprecated

#### Task 5.2: Update component docs
- Update all component CLAUDE.md files to reference UnifiedStorage
- Remove references to dual storage implementations

## Implementation Order

1. **CRITICAL FIRST**: Fix dual instance problem (Phase 1) - This fixes the OAuth bug
2. **Then**: Update imports (Phase 2) - Makes everything use unified storage
3. **Next**: Prevent direct access (Phase 3) - Enforces architecture
4. **Finally**: Test and document (Phases 4-5)

## Success Criteria

- [ ] Only ONE storage instance created during startup
- [ ] OAuth token refresh works without circular dependency
- [ ] All components use UnifiedStorage (no direct AsyncRedisStorage imports)
- [ ] No deprecation warnings in normal operation
- [ ] Tests pass confirming single instance and OAuth fix

## Rollback Plan

If issues arise:
1. Revert async_redis_storage.py move
2. Remove deprecation wrapper
3. Keep UnifiedStorage but allow direct AsyncRedisStorage use
4. Gradual migration component by component

## Timeline

- **Day 1**: Implement Phase 1 (fix dual instance) - CRITICAL
- **Day 2**: Implement Phase 2 (update imports)
- **Day 3**: Implement Phase 3 (prevent direct access)
- **Day 4**: Testing and documentation
- **Week 2**: Remove deprecation wrappers after stable operation