"""Async trace context for distributed tracing.

Implements W3C Trace Context standard with pure async operations.
Uses Python's contextvars for async-safe context propagation.
"""

import asyncio
import contextvars
import json
import secrets
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field


# Context variable for async trace propagation
current_trace = contextvars.ContextVar('current_trace', default=None)


@dataclass
class TraceContext:
    """W3C Trace Context with async operations.
    
    Follows W3C Trace Context specification for distributed tracing.
    """
    
    trace_id: str = field(default_factory=lambda: secrets.token_hex(16))  # 32 hex chars
    parent_id: Optional[str] = field(default=None)
    span_id: str = field(default_factory=lambda: secrets.token_hex(8))  # 16 hex chars
    trace_flags: int = field(default=1)  # 01 = sampled
    trace_state: Dict[str, str] = field(default_factory=dict)
    
    # Additional metadata
    operation: str = field(default="unknown")
    start_time: float = field(default_factory=time.time)
    spans: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_header(self) -> str:
        """Convert to W3C traceparent header format.
        
        Format: version-trace_id-parent_id-trace_flags
        Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
        """
        parent = self.parent_id or self.span_id
        return f"00-{self.trace_id}-{parent}-{self.trace_flags:02x}"
    
    @classmethod
    def from_header(cls, header: str) -> Optional['TraceContext']:
        """Parse W3C traceparent header.
        
        Args:
            header: Traceparent header string
            
        Returns:
            TraceContext or None if invalid
        """
        try:
            parts = header.split('-')
            if len(parts) != 4:
                return None
            
            version, trace_id, parent_id, flags = parts
            
            if version != "00":
                return None  # Only support version 00
            
            return cls(
                trace_id=trace_id,
                parent_id=parent_id,
                trace_flags=int(flags, 16)
            )
        except Exception:
            return None
    
    def create_child(self) -> 'TraceContext':
        """Create a child trace context for nested operations."""
        return TraceContext(
            trace_id=self.trace_id,
            parent_id=self.span_id,
            trace_flags=self.trace_flags,
            trace_state=self.trace_state.copy()
        )


class AsyncTraceManager:
    """Manages trace contexts with pure async operations."""
    
    def __init__(self, redis_client):
        """Initialize with Redis client.
        
        Args:
            redis_client: Async Redis client for trace storage
        """
        self.redis = redis_client
    
    def start_trace(self, operation: str, **metadata) -> TraceContext:
        """Start a new trace context.
        
        This is synchronous as it just creates the context object.
        The actual Redis operations are fire-and-forget.
        
        Args:
            operation: Name of the operation
            **metadata: Additional trace metadata
            
        Returns:
            New TraceContext
        """
        trace = TraceContext(operation=operation, **metadata)
        
        # Set as current trace in context
        current_trace.set(trace)
        
        # Fire-and-forget Redis storage
        asyncio.create_task(self._store_trace(trace))
        
        return trace
    
    def get_current_trace(self) -> Optional[TraceContext]:
        """Get the current trace context.
        
        Returns:
            Current TraceContext or None
        """
        return current_trace.get()
    
    def add_span(self, name: str, **data) -> None:
        """Add a span to the current trace.
        
        Fire-and-forget operation.
        
        Args:
            name: Span name
            **data: Span data
        """
        trace = self.get_current_trace()
        if trace:
            span = {
                "name": name,
                "span_id": secrets.token_hex(8),
                "timestamp": time.time(),
                "data": data
            }
            trace.spans.append(span)
            
            # Fire-and-forget Redis update
            asyncio.create_task(self._add_span_to_redis(trace.trace_id, span))
    
    async def _store_trace(self, trace: TraceContext) -> None:
        """Store trace metadata in Redis.
        
        Args:
            trace: TraceContext to store
        """
        try:
            trace_data = {
                "trace_id": trace.trace_id,
                "parent_id": trace.parent_id,
                "span_id": trace.span_id,
                "operation": trace.operation,
                "start_time": trace.start_time,
                "trace_flags": trace.trace_flags,
                "trace_state": json.dumps(trace.trace_state)
            }
            
            # Store with TTL
            await self.redis.hset(
                f"trace:{trace.trace_id}",
                mapping=trace_data
            )
            await self.redis.expire(f"trace:{trace.trace_id}", 86400)  # 24 hours
            
            # Add to trace index
            await self.redis.zadd(
                "idx:traces",
                {trace.trace_id: trace.start_time}
            )
            
        except Exception:
            # Never let trace storage errors affect the application
            pass
    
    async def _add_span_to_redis(self, trace_id: str, span: Dict[str, Any]) -> None:
        """Add a span to Redis.
        
        Args:
            trace_id: Trace ID
            span: Span data
        """
        try:
            # Store span in Redis list
            await self.redis.rpush(
                f"trace:{trace_id}:spans",
                json.dumps(span)
            )
            await self.redis.expire(f"trace:{trace_id}:spans", 86400)  # 24 hours
            
        except Exception:
            # Never let span storage errors affect the application
            pass
    
    async def get_trace(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """Get trace data from Redis.
        
        Args:
            trace_id: Trace ID to retrieve
            
        Returns:
            Trace data dict or None
        """
        try:
            # Get trace metadata
            trace_data = await self.redis.hgetall(f"trace:{trace_id}")
            if not trace_data:
                return None
            
            # Convert bytes to strings
            result = {}
            for key, value in trace_data.items():
                key_str = key.decode() if isinstance(key, bytes) else key
                val_str = value.decode() if isinstance(value, bytes) else value
                result[key_str] = val_str
            
            # Get spans
            spans_raw = await self.redis.lrange(f"trace:{trace_id}:spans", 0, -1)
            result["spans"] = []
            for span_json in spans_raw:
                span_str = span_json.decode() if isinstance(span_json, bytes) else span_json
                result["spans"].append(json.loads(span_str))
            
            return result
            
        except Exception:
            return None
    
    async def end_trace(self, trace_id: str, status: str = "success", **metadata) -> None:
        """End a trace and store final metadata.
        
        Args:
            trace_id: Trace ID to end
            status: Final status
            **metadata: Additional end metadata
        """
        try:
            end_time = time.time()
            
            # Update trace with end metadata
            await self.redis.hset(
                f"trace:{trace_id}",
                mapping={
                    "end_time": end_time,
                    "status": status,
                    "end_metadata": json.dumps(metadata)
                }
            )
            
            # Calculate duration
            start_time = await self.redis.hget(f"trace:{trace_id}", "start_time")
            if start_time:
                duration = end_time - float(start_time)
                await self.redis.hset(f"trace:{trace_id}", "duration_ms", int(duration * 1000))
            
        except Exception:
            # Never let trace ending errors affect the application
            pass
    
    def propagate_trace(self, headers: Dict[str, str]) -> Optional[TraceContext]:
        """Extract and propagate trace context from headers.
        
        Args:
            headers: HTTP headers dict
            
        Returns:
            TraceContext if found and valid
        """
        # Look for W3C traceparent header
        traceparent = headers.get("traceparent")
        if traceparent:
            trace = TraceContext.from_header(traceparent)
            if trace:
                # Set as current trace
                current_trace.set(trace)
                
                # Fire-and-forget storage
                asyncio.create_task(self._store_trace(trace))
                
                return trace
        
        return None
    
    def inject_trace(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Inject current trace context into headers.
        
        Args:
            headers: Headers dict to modify
            
        Returns:
            Modified headers dict
        """
        trace = self.get_current_trace()
        if trace:
            headers["traceparent"] = trace.to_header()
            
            # Add tracestate if present
            if trace.trace_state:
                state_parts = [f"{k}={v}" for k, v in trace.trace_state.items()]
                headers["tracestate"] = ",".join(state_parts)
        
        return headers


# Convenience functions for fire-and-forget trace operations

def start_trace(operation: str, **metadata) -> str:
    """Start a new trace and return trace ID.
    
    Fire-and-forget operation.
    
    Args:
        operation: Operation name
        **metadata: Trace metadata
        
    Returns:
        Trace ID
    """
    trace = TraceContext(operation=operation, **metadata)
    current_trace.set(trace)
    return trace.trace_id


def add_trace_span(name: str, **data) -> None:
    """Add a span to the current trace.
    
    Fire-and-forget operation.
    
    Args:
        name: Span name
        **data: Span data
    """
    trace = current_trace.get()
    if trace:
        span = {
            "name": name,
            "span_id": secrets.token_hex(8),
            "timestamp": time.time(),
            "data": data
        }
        trace.spans.append(span)


def get_trace_id() -> Optional[str]:
    """Get current trace ID.
    
    Returns:
        Trace ID or None
    """
    trace = current_trace.get()
    return trace.trace_id if trace else None