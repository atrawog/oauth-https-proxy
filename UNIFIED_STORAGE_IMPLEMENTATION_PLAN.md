# Comprehensive Implementation Plan: Unified Storage Architecture

## Executive Summary

This plan addresses the critical OAuth token refresh bug caused by dual storage implementations (RedisStorage and AsyncRedisStorage) that operate independently. The solution leverages production-tested libraries (redis-py and asgiref) to create a unified storage architecture with zero code duplication.

## Problem Analysis

### Root Cause Chain
1. **Surface Symptom**: OAuth token refresh fails with "Token refresh failed - please run: proxy-client oauth login"
2. **Direct Cause**: `/token` endpoint requires authentication, creating circular dependency
3. **Underlying Issue**: `auth_excluded_paths` not set on localhost proxy in AsyncRedisStorage
4. **Root Problem**: Two independent storage implementations (sync and async) with divergent initialization
5. **Design Flaw**: No single source of truth for business logic

### Current Architecture Problems
- **Code Duplication**: ~2000 lines duplicated between RedisStorage and AsyncRedisStorage
- **Initialization Divergence**: Only sync storage calls `initialize_default_proxies()`
- **Maintenance Burden**: Every change must be made twice
- **Synchronization Issues**: Changes in one storage don't reflect in the other
- **Testing Complexity**: Need to test both implementations separately

## Proposed Solution: Unified Storage with asgiref Bridge

### Architecture Decision Records (ADR)

#### ADR-001: Use asgiref for Sync/Async Bridge
**Decision**: Use Django's asgiref library instead of custom event loop management
**Rationale**:
- Production-tested in Django at scale
- Handles edge cases (nested loops, thread safety)
- Simpler than managing dedicated event loops
- Better error handling and debugging

#### ADR-002: Single Source of Truth in AsyncRedisStorage
**Decision**: All business logic lives in AsyncRedisStorage only
**Rationale**:
- Eliminates code duplication
- Single place for bug fixes
- Consistent behavior across sync/async contexts
- Easier testing and maintenance

#### ADR-003: Leverage redis-py Native Features
**Decision**: Use redis-py's built-in connection pools and clients
**Rationale**:
- Thread-safe by design
- Automatic reconnection
- Health checks included
- Performance optimized

#### ADR-004: Compatibility Shims for Migration
**Decision**: Provide RedisStorage/AsyncRedisStorage as thin wrappers
**Rationale**:
- Zero breaking changes
- Gradual migration possible
- Existing code continues working
- Can deprecate slowly

## Implementation Plan

### Phase 1: Foundation (Day 1)

#### Task 1.1: Add Dependencies
```toml
# pixi.toml
asgiref = ">=3.7.2"  # Django's sync/async bridge
```

#### Task 1.2: Create UnifiedStorage Class
```python
# src/storage/unified_storage.py
"""Unified storage implementation using asgiref for sync/async bridge.

This module provides a single storage interface that works in both
sync and async contexts, eliminating code duplication.
"""

import asyncio
from typing import Optional, Any
import redis
import redis.asyncio as redis_async
from asgiref.sync import sync_to_async, async_to_sync

class UnifiedStorage:
    """Unified storage that bridges sync and async contexts.
    
    Architecture:
    - Single source of truth: AsyncRedisStorage
    - Automatic sync/async conversion using asgiref
    - Zero code duplication
    - Thread-safe Redis operations
    """
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._async_pool: Optional[redis_async.ConnectionPool] = None
        self._async_storage: Optional['AsyncRedisStorage'] = None
        self._initialized = False
        
    def initialize(self):
        """Synchronous initialization for legacy components."""
        if self._initialized:
            return
        
        # Use async_to_sync to run async initialization
        async_to_sync(self._initialize_async)()
        self._initialized = True
        
    async def initialize_async(self):
        """Asynchronous initialization for async components."""
        if self._initialized:
            return
            
        await self._initialize_async()
        self._initialized = True
        
    async def _initialize_async(self):
        """Core initialization logic (async)."""
        # Create connection pool using redis-py
        self._async_pool = redis_async.ConnectionPool.from_url(
            self.redis_url,
            decode_responses=True,
            max_connections=50,
            health_check_interval=30
        )
        
        # Initialize AsyncRedisStorage with the pool
        from .async_redis_storage import AsyncRedisStorage
        self._async_storage = AsyncRedisStorage(self.redis_url)
        self._async_storage.redis_client = redis_async.Redis(
            connection_pool=self._async_pool
        )
        
        # CRITICAL: Initialize defaults (fixes OAuth bug)
        await self._async_storage.initialize_default_proxies()
        await self._async_storage.initialize_default_routes()
        
    def __getattr__(self, name: str) -> Any:
        """Smart method delegation with automatic sync/async conversion."""
        if not self._initialized:
            self.initialize()  # Auto-initialize on first use
            
        attr = getattr(self._async_storage, name)
        
        # Non-coroutine attributes pass through
        if not asyncio.iscoroutinefunction(attr):
            return attr
            
        # Check execution context
        try:
            asyncio.get_running_loop()
            # In async context, return async method directly
            return attr
        except RuntimeError:
            # In sync context, wrap with async_to_sync
            # thread_sensitive=False for Redis (thread-safe)
            return async_to_sync(attr, thread_sensitive=False)
            
    def close(self):
        """Synchronous cleanup."""
        if self._async_storage and self._async_pool:
            async_to_sync(self._cleanup)()
            
    async def close_async(self):
        """Asynchronous cleanup."""
        await self._cleanup()
        
    async def _cleanup(self):
        """Core cleanup logic."""
        if self._async_storage:
            await self._async_storage.close()
        if self._async_pool:
            await self._async_pool.disconnect()
```

#### Task 1.3: Update AsyncRedisStorage
```python
# src/storage/async_redis_storage.py (modifications)

class AsyncRedisStorage:
    """Pure async storage implementation - single source of truth."""
    
    async def initialize_default_proxies(self):
        """Initialize default proxies with proper auth configuration.
        
        CRITICAL FIX: This ensures localhost proxy has auth_excluded_paths
        to prevent circular dependency in OAuth token refresh.
        """
        from ..proxy.models import DEFAULT_PROXIES
        
        for proxy_dict in DEFAULT_PROXIES:
            hostname = proxy_dict["proxy_hostname"]
            existing = await self.get_proxy_target(hostname)
            
            if not existing:
                # Create with all defaults including auth_excluded_paths
                from ..proxy.models import ProxyTarget
                target = ProxyTarget(**proxy_dict)
                await self.store_proxy_target(hostname, target)
                log_info(f"Created default proxy: {hostname}", component="storage")
                
            elif hostname == "localhost" and not existing.auth_excluded_paths:
                # FIX: Ensure localhost has auth_excluded_paths
                updates = {"auth_excluded_paths": proxy_dict.get("auth_excluded_paths")}
                await self.update_proxy_target(hostname, updates)
                log_info(f"Updated localhost proxy with auth_excluded_paths", component="storage")
                
    async def initialize_default_routes(self):
        """Initialize default routes for system operation."""
        # ... existing implementation
```

### Phase 2: Compatibility Layer (Day 1)

#### Task 2.1: Create Compatibility Shims
```python
# src/storage/__init__.py
"""Storage module with unified architecture and compatibility shims."""

from .unified_storage import UnifiedStorage

# Compatibility shim for old RedisStorage
class RedisStorage(UnifiedStorage):
    """Drop-in replacement for legacy RedisStorage.
    
    This is a thin wrapper around UnifiedStorage that maintains
    backward compatibility with sync-only code.
    """
    
    def __init__(self, redis_url: str):
        super().__init__(redis_url)
        # Auto-initialize for backward compatibility
        self.initialize()
        
    # All methods inherited from UnifiedStorage work automatically

# Compatibility shim for old AsyncRedisStorage  
class AsyncRedisStorage(UnifiedStorage):
    """Drop-in replacement for legacy AsyncRedisStorage.
    
    This is a thin wrapper around UnifiedStorage that maintains
    backward compatibility with async-only code.
    """
    
    async def initialize(self):
        """Async initialization for compatibility."""
        await self.initialize_async()
        
    # All methods inherited from UnifiedStorage work automatically

# Export all three for flexibility
__all__ = ['UnifiedStorage', 'RedisStorage', 'AsyncRedisStorage']
```

#### Task 2.2: Remove Old Implementations
```bash
# Move old implementations to backup
mv src/storage/redis_storage.py src/storage/redis_storage.py.old
mv src/storage/async_redis_storage.py src/storage/async_redis_storage_original.py

# Rename async_redis_storage_original.py back to async_redis_storage.py
# (Keep it as the single source of truth, just remove sync version)
mv src/storage/async_redis_storage_original.py src/storage/async_redis_storage.py
```

### Phase 3: Testing & Validation (Day 2)

#### Task 3.1: Create Comprehensive Tests
```python
# tests/test_unified_storage.py
import pytest
import asyncio
from src.storage import UnifiedStorage, RedisStorage, AsyncRedisStorage

class TestUnifiedStorage:
    """Test unified storage in all contexts."""
    
    def test_sync_initialization(self, redis_url):
        """Test sync init and operations."""
        storage = UnifiedStorage(redis_url)
        storage.initialize()
        
        # Verify localhost proxy has auth_excluded_paths (OAuth fix)
        proxy = storage.get_proxy_target("localhost")
        assert proxy is not None
        assert proxy.auth_excluded_paths is not None
        assert "/token" in proxy.auth_excluded_paths
        
    @pytest.mark.asyncio
    async def test_async_initialization(self, redis_url):
        """Test async init and operations."""
        storage = UnifiedStorage(redis_url)
        await storage.initialize_async()
        
        # Verify localhost proxy configuration
        proxy = await storage.get_proxy_target("localhost")
        assert proxy is not None
        assert proxy.auth_excluded_paths is not None
        assert "/token" in proxy.auth_excluded_paths
        
    def test_backward_compatibility_sync(self, redis_url):
        """Test RedisStorage compatibility shim."""
        # Should work exactly like old RedisStorage
        storage = RedisStorage(redis_url)  # Auto-initializes
        
        proxy = storage.get_proxy_target("localhost")
        assert proxy is not None
        
    @pytest.mark.asyncio
    async def test_backward_compatibility_async(self, redis_url):
        """Test AsyncRedisStorage compatibility shim."""
        # Should work exactly like old AsyncRedisStorage
        storage = AsyncRedisStorage(redis_url)
        await storage.initialize()
        
        proxy = await storage.get_proxy_target("localhost")
        assert proxy is not None
        
    def test_oauth_token_refresh_fix(self, redis_url):
        """Verify OAuth token refresh bug is fixed."""
        storage = UnifiedStorage(redis_url)
        storage.initialize()
        
        proxy = storage.get_proxy_target("localhost")
        
        # Critical assertions for OAuth fix
        assert proxy.auth_excluded_paths is not None
        assert "/token" in proxy.auth_excluded_paths
        assert "/authorize" in proxy.auth_excluded_paths
        assert "/device/" in proxy.auth_excluded_paths
```

#### Task 3.2: Integration Testing
```bash
# Test OAuth token refresh
just oauth-login
just oauth-refresh  # Should work without circular dependency

# Test all storage operations
just test tests/test_unified_storage.py -v

# Test existing code still works
just test tests/test_storage.py -v
```

### Phase 4: Documentation (Day 2)

#### Task 4.1: Update Storage Documentation
```markdown
# src/storage/CLAUDE.md (additions)

## Unified Storage Architecture

### Overview
The storage layer uses a unified architecture that eliminates code duplication
between sync and async contexts. All business logic lives in AsyncRedisStorage,
with UnifiedStorage providing automatic sync/async conversion.

### Architecture Decision: Why Unified Storage?

#### The Problem
Originally, we had two separate implementations:
- `RedisStorage`: Synchronous implementation for ACME, main.py, dispatcher
- `AsyncRedisStorage`: Asynchronous implementation for API, proxy handlers

This caused:
1. **Code Duplication**: ~2000 lines of duplicated logic
2. **Initialization Bugs**: Only sync storage initialized defaults
3. **OAuth Bug**: Token refresh failed due to missing auth_excluded_paths
4. **Maintenance Burden**: Every fix needed to be applied twice

#### The Solution
UnifiedStorage uses:
- **asgiref**: Django's production-tested sync/async bridge
- **redis-py**: Native connection pooling and thread safety
- **Single Source**: All logic in AsyncRedisStorage only

### How It Works

1. **Context Detection**: UnifiedStorage detects if caller is sync or async
2. **Automatic Conversion**: Uses asgiref's async_to_sync for sync callers
3. **Direct Pass-through**: Async callers get native async methods
4. **Zero Duplication**: All business logic in one place

### Usage Examples

#### Sync Context (ACME, Certificate Manager)
```python
from storage import UnifiedStorage

storage = UnifiedStorage(redis_url)
storage.initialize()  # Sync initialization

# All operations are synchronous
cert = storage.get_certificate("example-cert")
proxy = storage.get_proxy_target("localhost")
```

#### Async Context (API, Proxy Handlers)
```python
from storage import UnifiedStorage

storage = UnifiedStorage(redis_url)
await storage.initialize_async()  # Async initialization

# All operations are asynchronous
cert = await storage.get_certificate("example-cert")
proxy = await storage.get_proxy_target("localhost")
```

#### Mixed Context (Flexible Components)
```python
class FlexibleComponent:
    def __init__(self, storage: UnifiedStorage):
        self.storage = storage
        
    def sync_method(self):
        # Automatically uses sync version
        return self.storage.get_proxy_target("localhost")
        
    async def async_method(self):
        # Automatically uses async version
        return await self.storage.get_proxy_target("localhost")
```

### Migration Guide

#### For New Code
Use `UnifiedStorage` directly:
```python
from storage import UnifiedStorage
storage = UnifiedStorage(redis_url)
```

#### For Existing Code
No changes needed! Compatibility shims maintain backward compatibility:
- `RedisStorage` → Works as before (wraps UnifiedStorage)
- `AsyncRedisStorage` → Works as before (wraps UnifiedStorage)

### Technical Details

#### Connection Pooling
- Uses redis-py's native `ConnectionPool`
- Separate pools for sync and async operations
- Configurable max connections and health checks

#### Thread Safety
- Redis operations are thread-safe via redis-py
- asgiref manages thread pools correctly
- No custom thread management needed

#### Performance
- Connection pooling reduces overhead
- Thread pool reuse via asgiref
- No unnecessary event loop creation
- Single Redis connection per context

### OAuth Bug Fix
The unified architecture fixes the OAuth token refresh bug by ensuring
`initialize_default_proxies()` is called in both sync and async paths.
This sets `auth_excluded_paths` on the localhost proxy, preventing the
circular dependency where the token endpoint requires authentication.
```

#### Task 4.2: Update Main Documentation
```markdown
# CLAUDE.md (additions)

## Storage Architecture

### Unified Storage Implementation
The system uses a unified storage architecture that supports both synchronous
and asynchronous operations without code duplication. This is achieved through:

- **Single Implementation**: All logic in AsyncRedisStorage
- **Smart Bridge**: UnifiedStorage with asgiref for sync/async conversion
- **Zero Duplication**: No repeated code between sync and async
- **Backward Compatible**: Existing code continues working

See [Storage Documentation](src/storage/CLAUDE.md) for details.

## Fixed Issues

### OAuth Token Refresh Bug (Fixed)
- **Problem**: Token refresh failed with circular dependency
- **Cause**: Dual storage implementations with divergent initialization
- **Solution**: Unified storage ensures consistent initialization
- **Result**: OAuth token refresh now works correctly
```

### Phase 5: Deployment (Day 3)

#### Task 5.1: Deploy Changes
```bash
# 1. Add asgiref dependency
pixi add asgiref

# 2. Deploy new storage implementation
cp unified_storage.py src/storage/
cp compatibility_shims.py src/storage/__init__.py

# 3. Test in development
just down
just up
just oauth-login
just oauth-refresh  # Should work!

# 4. Run full test suite
just test-all
```

#### Task 5.2: Monitor and Validate
```bash
# Monitor logs for any issues
just logs-follow | grep -E "storage|oauth|redis"

# Verify OAuth flow
just oauth-status

# Check Redis connections
just redis-cli INFO clients
```

### Phase 6: Cleanup (Week 2)

#### Task 6.1: Remove Old Code
After 1 week of stable operation:
```bash
# Remove backup files
rm src/storage/redis_storage.py.old

# Remove compatibility imports from components
# (Gradual migration to UnifiedStorage)
```

#### Task 6.2: Update All Components
Gradually update components to use UnifiedStorage directly:
```python
# main.py
- from .storage import RedisStorage
+ from .storage import UnifiedStorage

# api/async_init.py  
- from ..storage import AsyncRedisStorage
+ from ..storage import UnifiedStorage
```

## Success Metrics

1. **OAuth Token Refresh**: Works without manual intervention
2. **Code Reduction**: ~2000 lines removed (50% reduction)
3. **Test Coverage**: 100% of storage operations tested
4. **Performance**: No degradation in response times
5. **Zero Downtime**: Migration without service interruption

## Risk Mitigation

1. **Compatibility Shims**: Ensure zero breaking changes
2. **Extensive Testing**: Test in dev before production
3. **Gradual Migration**: Can rollback if issues arise
4. **Monitoring**: Watch logs and metrics closely
5. **Documentation**: Clear migration guide for team

## Timeline

- **Day 1**: Implement UnifiedStorage and compatibility layer
- **Day 2**: Testing and documentation
- **Day 3**: Deploy to development environment
- **Week 1**: Monitor and fix any edge cases
- **Week 2**: Begin removing old code and updating components

This plan provides a robust solution to the storage duplication problem while fixing the critical OAuth bug and establishing a maintainable architecture for the future.