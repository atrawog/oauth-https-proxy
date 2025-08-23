"""Metrics processor consumer for real-time metrics from streams.

This consumer processes events and logs from Redis Streams to generate
real-time metrics and statistics.
"""

import asyncio
import json
import time
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime, timezone

from .unified_consumer import UnifiedStreamConsumer
import redis.asyncio as redis_async
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace


class MetricsProcessor(UnifiedStreamConsumer):
    """Processes streams to generate real-time metrics."""
    
    def __init__(self, redis_client: redis_async.Redis):
        """Initialize the metrics processor.
        
        Args:
            redis_client: Async Redis client
        """
        super().__init__(
            redis_client=redis_client,
            group_name="metrics-group",
            consumer_name=f"metrics-processor-{int(time.time())}"
        )
        
        # Add streams to consume
        self.add_stream("logs:request:stream")
        self.add_stream("logs:system:stream")
        self.add_stream("logs:error:stream")
        self.add_stream("events:proxy:stream")
        self.add_stream("events:certificate:stream")
        self.add_stream("events:service:stream")
        
        # Register handlers
        self.register_handler("http_", self.process_http_metrics)
        self.register_handler("service_", self.process_service_metrics)
        self.register_handler("certificate_", self.process_cert_metrics)
        self.register_handler("proxy_", self.process_proxy_metrics)
        self.register_handler("error", self.process_error_metrics)
        
        # Metrics storage
        self.response_times: Dict[str, List[float]] = defaultdict(list)
        self.status_counts: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.unique_ips: Dict[str, set] = defaultdict(set)
        
        # Aggregation task
        self.aggregation_task: Optional[asyncio.Task] = None
        self.aggregation_interval = 60  # Aggregate every minute
    
    async def start(self):
        """Start the metrics processor."""
        await super().start()
        
        # Start aggregation task
        self.aggregation_task = asyncio.create_task(self._aggregation_loop())
        log_info("Started metrics aggregation task", component="metrics_processor")
    
    async def stop(self):
        """Stop the metrics processor."""
        # Stop aggregation task
        if self.aggregation_task:
            self.aggregation_task.cancel()
            try:
                await self.aggregation_task
            except asyncio.CancelledError:
                pass
        
        # Flush final metrics
        await self._aggregate_metrics()
        
        await super().stop()
    
    async def _aggregation_loop(self):
        """Periodically aggregate and store metrics."""
        while self.running:
            try:
                await asyncio.sleep(self.aggregation_interval)
                await self._aggregate_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log_error(f"Aggregation error: {e}", component="metrics_processor", error=e)
    
    async def _aggregate_metrics(self):
        """Aggregate collected metrics and store in Redis."""
        try:
            current_hour = datetime.now(timezone.utc).strftime("%Y%m%d:%H")
            
            # Aggregate per-hostname metrics
            for proxy_hostname in set(list(self.response_times.keys()) + 
                              list(self.status_counts.keys()) + 
                              list(self.unique_ips.keys())):
                
                metrics = {}
                
                # Response time statistics
                if proxy_hostname in self.response_times:
                    times = self.response_times[proxy_hostname]
                    if times:
                        metrics["response_time_avg"] = sum(times) / len(times)
                        metrics["response_time_min"] = min(times)
                        metrics["response_time_max"] = max(times)
                        metrics["response_time_p50"] = self._percentile(times, 50)
                        metrics["response_time_p95"] = self._percentile(times, 95)
                        metrics["response_time_p99"] = self._percentile(times, 99)
                        metrics["request_count"] = len(times)
                    
                    # Clear after aggregation
                    self.response_times[proxy_hostname] = self.response_times[proxy_hostname][-1000:]  # Keep last 1000
                
                # Status code distribution
                if proxy_hostname in self.status_counts:
                    metrics["status_codes"] = dict(self.status_counts[proxy_hostname])
                    
                    # Calculate error rate
                    total = sum(self.status_counts[proxy_hostname].values())
                    errors = sum(count for status, count in self.status_counts[proxy_hostname].items() 
                               if status >= 400)
                    metrics["error_rate"] = (errors / total * 100) if total > 0 else 0
                
                # Unique visitors
                if proxy_hostname in self.unique_ips:
                    metrics["unique_visitors"] = len(self.unique_ips[proxy_hostname])
                    # Use HyperLogLog for memory efficiency
                    await self.redis.pfadd(
                        f"stats:unique_ips:{proxy_hostname}:{current_hour}",
                        *self.unique_ips[proxy_hostname]
                    )
                    self.unique_ips[proxy_hostname].clear()
                
                # Store aggregated metrics
                if metrics:
                    await self.redis.hset(
                        f"metrics:{proxy_hostname}:{current_hour}",
                        mapping={k: json.dumps(v) if isinstance(v, dict) else str(v) 
                                for k, v in metrics.items()}
                    )
                    await self.redis.expire(f"metrics:{proxy_hostname}:{current_hour}", 86400 * 7)  # 7 days
            
            # Store global error metrics
            if self.error_counts:
                await self.redis.hset(
                    f"metrics:errors:{current_hour}",
                    mapping={k: str(v) for k, v in self.error_counts.items()}
                )
                await self.redis.expire(f"metrics:errors:{current_hour}", 86400 * 7)
            
            log_info(f"Aggregated metrics for {len(self.response_times)} proxy_hostnames", component="metrics_processor")
            
        except Exception as e:
            log_error(f"Failed to aggregate metrics: {e}", component="metrics_processor", error=e)
    
    def _percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile of values.
        
        Args:
            values: List of numeric values
            percentile: Percentile to calculate (0-100)
            
        Returns:
            Percentile value
        """
        if not values:
            return 0
        
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile / 100)
        return sorted_values[min(index, len(sorted_values) - 1)]
    
    # Handler methods
    
    async def process_http_metrics(self, stream: str, msg_id: str, data: dict):
        """Process HTTP request/response metrics.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: Parsed message data
        """
        try:
            proxy_hostname = data.get("proxy_hostname", "unknown")
            
            # Process response metrics
            if data.get("log_type") == "http_response" or "duration_ms" in data:
                duration = data.get("duration_ms")
                if duration is not None:
                    self.response_times[proxy_hostname].append(float(duration))
                
                status = data.get("status")
                if status is not None:
                    self.status_counts[proxy_hostname][int(status)] += 1
            
            # Track unique IPs
            client_ip = data.get("client_ip")
            if client_ip:
                self.unique_ips[proxy_hostname].add(client_ip)
            
            # Update real-time counters
            await self.redis.hincrby(
                f"stats:realtime:{proxy_hostname}",
                "requests",
                1
            )
            await self.redis.expire(f"stats:realtime:{proxy_hostname}", 300)  # 5 min TTL
            
        except Exception as e:
            log_error(f"Failed to process HTTP metrics: {e}", component="metrics_processor", error=e)
    
    async def process_service_metrics(self, stream: str, msg_id: str, data: dict):
        """Process service lifecycle metrics.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: Parsed message data
        """
        try:
            event_type = data.get("event_type", "")
            service_name = data.get("service_name", "unknown")
            
            # Track service events
            await self.redis.hincrby(
                f"stats:services:{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                event_type,
                1
            )
            
            # Update service status
            if "created" in event_type or "started" in event_type:
                await self.redis.hset("service:status", service_name, "running")
            elif "stopped" in event_type or "deleted" in event_type:
                await self.redis.hset("service:status", service_name, "stopped")
            elif "failed" in event_type:
                await self.redis.hset("service:status", service_name, "failed")
                self.error_counts[f"service:{service_name}"] += 1
            
        except Exception as e:
            log_error(f"Failed to process service metrics: {e}", component="metrics_processor", error=e)
    
    async def process_cert_metrics(self, stream: str, msg_id: str, data: dict):
        """Process certificate lifecycle metrics.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: Parsed message data
        """
        try:
            event_type = data.get("event_type", "")
            cert_name = data.get("cert_name", "unknown")
            
            # Track certificate events
            await self.redis.hincrby(
                f"stats:certificates:{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                event_type,
                1
            )
            
            # Track certificate status
            if "ready" in event_type or "renewed" in event_type:
                expires_at = data.get("expires_at")
                await self.redis.hset(
                    "cert:status",
                    cert_name,
                    json.dumps({
                        "status": "active",
                        "expires_at": expires_at,
                        "updated_at": datetime.now(timezone.utc).isoformat()
                    })
                )
            elif "failed" in event_type:
                self.error_counts[f"cert:{cert_name}"] += 1
                await self.redis.hset(
                    "cert:status",
                    cert_name,
                    json.dumps({
                        "status": "failed",
                        "updated_at": datetime.now(timezone.utc).isoformat()
                    })
                )
            
        except Exception as e:
            log_error(f"Failed to process certificate metrics: {e}", component="metrics_processor", error=e)
    
    async def process_proxy_metrics(self, stream: str, msg_id: str, data: dict):
        """Process proxy lifecycle metrics.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: Parsed message data
        """
        try:
            event_type = data.get("event_type", "")
            proxy_hostname = data.get("proxy_hostname", data.get("hostname", "unknown"))
            
            # Track proxy events
            await self.redis.hincrby(
                f"stats:proxies:{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                event_type,
                1
            )
            
            # Update proxy count
            if "created" in event_type:
                await self.redis.sadd("proxies:active", proxy_hostname)
            elif "deleted" in event_type:
                await self.redis.srem("proxies:active", proxy_hostname)
            
        except Exception as e:
            log_error(f"Failed to process proxy metrics: {e}", component="metrics_processor", error=e)
    
    async def process_error_metrics(self, stream: str, msg_id: str, data: dict):
        """Process error metrics.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: Parsed message data
        """
        try:
            component = data.get("component", "unknown")
            exception_type = data.get("exception_type", "unknown")
            
            # Track errors by component
            self.error_counts[f"component:{component}"] += 1
            
            # Track errors by type
            self.error_counts[f"exception:{exception_type}"] += 1
            
            # Store recent errors for debugging
            await self.redis.lpush(
                "errors:recent",
                json.dumps({
                    "timestamp": data.get("timestamp", time.time()),
                    "component": component,
                    "exception": exception_type,
                    "message": data.get("message", ""),
                    "trace_id": data.get("trace_id", "")
                })
            )
            await self.redis.ltrim("errors:recent", 0, 999)  # Keep last 1000
            
        except Exception as e:
            log_error(f"Failed to process error metrics: {e}", component="metrics_processor", error=e)
    
    async def handle_unknown(self, stream: str, msg_id: str, data: dict):
        """Handle messages with no matching handler.
        
        Args:
            stream: Stream the message came from
            msg_id: Message ID
            data: Parsed message data
        """
        # Just count unknown messages
        await self.redis.hincrby("stats:unknown_messages", stream, 1)