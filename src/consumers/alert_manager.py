"""Alert manager consumer for monitoring and alerting from streams.

This consumer monitors events and logs from Redis Streams to detect
anomalies and trigger alerts.
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Set
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from .unified_consumer import UnifiedStreamConsumer
import redis.asyncio as redis_async

logger = logging.getLogger(__name__)


class AlertManager(UnifiedStreamConsumer):
    """Monitors streams for alert conditions and triggers notifications."""
    
    def __init__(self, redis_client: redis_async.Redis):
        """Initialize the alert manager.
        
        Args:
            redis_client: Async Redis client
        """
        super().__init__(
            redis_client=redis_client,
            group_name="alert-group",
            consumer_name=f"alert-manager-{int(time.time())}"
        )
        
        # Add streams to monitor
        self.add_stream("logs:error:stream")
        self.add_stream("events:service:stream")
        self.add_stream("events:certificate:stream")
        self.add_stream("logs:request:stream")
        
        # Register handlers
        self.register_handler("error", self.check_error_rate)
        self.register_handler("service_failed", self.alert_service_failure)
        self.register_handler("certificate_expiring", self.alert_cert_expiry)
        self.register_handler("certificate_failed", self.alert_cert_failure)
        self.register_handler("http_", self.check_response_time)
        
        # Alert thresholds
        self.error_rate_threshold = 10  # errors per 5 minutes
        self.error_rate_window = 300    # 5 minutes
        self.response_time_threshold = 5000  # 5 seconds
        self.response_time_spike_ratio = 3  # 3x normal
        
        # Tracking
        self.error_counts: Dict[str, List[float]] = defaultdict(list)
        self.response_times: Dict[str, List[float]] = defaultdict(list)
        self.active_alerts: Set[str] = set()
        self.alert_cooldown: Dict[str, float] = {}
        self.cooldown_period = 300  # 5 minutes between same alerts
        
        # Alert destinations (would be configured in production)
        self.webhook_url: Optional[str] = None
        self.email_recipients: List[str] = []
    
    async def check_error_rate(self, stream: str, msg_id: str, data: dict):
        """Check error rate and trigger alerts if threshold exceeded.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: Error event data
        """
        try:
            component = data.get("component", "unknown")
            timestamp = data.get("timestamp", time.time())
            
            # Track error timestamp
            self.error_counts[component].append(timestamp)
            
            # Clean old entries
            cutoff = time.time() - self.error_rate_window
            self.error_counts[component] = [
                ts for ts in self.error_counts[component] if ts > cutoff
            ]
            
            # Check threshold
            error_count = len(self.error_counts[component])
            if error_count > self.error_rate_threshold:
                alert_key = f"error_rate:{component}"
                
                if await self._should_alert(alert_key):
                    await self._send_alert(
                        severity="HIGH",
                        title=f"High Error Rate: {component}",
                        message=f"Component {component} has {error_count} errors in the last {self.error_rate_window/60:.0f} minutes",
                        details={
                            "component": component,
                            "error_count": error_count,
                            "window_minutes": self.error_rate_window / 60,
                            "threshold": self.error_rate_threshold,
                            "recent_error": data.get("message", "")
                        }
                    )
            
        except Exception as e:
            logger.error(f"Failed to check error rate: {e}")
    
    async def alert_service_failure(self, stream: str, msg_id: str, data: dict):
        """Alert on service failures.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: Service failure event
        """
        try:
            service_name = data.get("service_name", "unknown")
            error = data.get("error", "Unknown error")
            
            alert_key = f"service_failed:{service_name}"
            
            if await self._should_alert(alert_key):
                await self._send_alert(
                    severity="CRITICAL",
                    title=f"Service Failed: {service_name}",
                    message=f"Service {service_name} has failed: {error}",
                    details={
                        "service_name": service_name,
                        "error": error,
                        "timestamp": data.get("timestamp", time.time())
                    }
                )
            
        except Exception as e:
            logger.error(f"Failed to alert service failure: {e}")
    
    async def alert_cert_expiry(self, stream: str, msg_id: str, data: dict):
        """Alert on certificate expiry.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: Certificate expiry event
        """
        try:
            cert_name = data.get("cert_name", "unknown")
            expires_at = data.get("expires_at")
            days_remaining = data.get("days_remaining", 0)
            
            alert_key = f"cert_expiring:{cert_name}"
            
            # Different severity based on days remaining
            if days_remaining <= 7:
                severity = "CRITICAL"
            elif days_remaining <= 14:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
            
            if await self._should_alert(alert_key):
                await self._send_alert(
                    severity=severity,
                    title=f"Certificate Expiring: {cert_name}",
                    message=f"Certificate {cert_name} expires in {days_remaining} days",
                    details={
                        "cert_name": cert_name,
                        "expires_at": expires_at,
                        "days_remaining": days_remaining,
                        "domains": data.get("domains", [])
                    }
                )
            
        except Exception as e:
            logger.error(f"Failed to alert cert expiry: {e}")
    
    async def alert_cert_failure(self, stream: str, msg_id: str, data: dict):
        """Alert on certificate generation/renewal failures.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: Certificate failure event
        """
        try:
            cert_name = data.get("cert_name", "unknown")
            error = data.get("error", "Unknown error")
            operation = data.get("operation", "generation")
            
            alert_key = f"cert_failed:{cert_name}"
            
            if await self._should_alert(alert_key):
                await self._send_alert(
                    severity="HIGH",
                    title=f"Certificate {operation.title()} Failed: {cert_name}",
                    message=f"Failed to {operation} certificate {cert_name}: {error}",
                    details={
                        "cert_name": cert_name,
                        "operation": operation,
                        "error": error,
                        "domains": data.get("domains", [])
                    }
                )
            
        except Exception as e:
            logger.error(f"Failed to alert cert failure: {e}")
    
    async def check_response_time(self, stream: str, msg_id: str, data: dict):
        """Check response times for anomalies.
        
        Args:
            stream: Source stream
            msg_id: Message ID
            data: HTTP response data
        """
        try:
            if data.get("log_type") != "http_response":
                return
            
            hostname = data.get("hostname", "unknown")
            duration_ms = data.get("duration_ms")
            
            if duration_ms is None:
                return
            
            # Track response time
            self.response_times[hostname].append(duration_ms)
            
            # Keep only recent data (last 100 requests)
            if len(self.response_times[hostname]) > 100:
                self.response_times[hostname] = self.response_times[hostname][-100:]
            
            # Check for slow response
            if duration_ms > self.response_time_threshold:
                alert_key = f"slow_response:{hostname}"
                
                if await self._should_alert(alert_key):
                    await self._send_alert(
                        severity="MEDIUM",
                        title=f"Slow Response: {hostname}",
                        message=f"Response time {duration_ms:.0f}ms exceeds threshold {self.response_time_threshold}ms",
                        details={
                            "hostname": hostname,
                            "duration_ms": duration_ms,
                            "threshold_ms": self.response_time_threshold,
                            "path": data.get("path", ""),
                            "status": data.get("status", "")
                        }
                    )
            
            # Check for response time spike
            if len(self.response_times[hostname]) >= 10:
                recent_avg = sum(self.response_times[hostname][-10:]) / 10
                historical_avg = sum(self.response_times[hostname][:-10]) / len(self.response_times[hostname][:-10])
                
                if recent_avg > historical_avg * self.response_time_spike_ratio:
                    alert_key = f"response_spike:{hostname}"
                    
                    if await self._should_alert(alert_key):
                        await self._send_alert(
                            severity="MEDIUM",
                            title=f"Response Time Spike: {hostname}",
                            message=f"Recent avg {recent_avg:.0f}ms is {recent_avg/historical_avg:.1f}x normal ({historical_avg:.0f}ms)",
                            details={
                                "hostname": hostname,
                                "recent_avg_ms": recent_avg,
                                "historical_avg_ms": historical_avg,
                                "spike_ratio": recent_avg / historical_avg
                            }
                        )
            
        except Exception as e:
            logger.error(f"Failed to check response time: {e}")
    
    async def _should_alert(self, alert_key: str) -> bool:
        """Check if we should send an alert (respecting cooldown).
        
        Args:
            alert_key: Unique key for the alert
            
        Returns:
            True if alert should be sent
        """
        # Check cooldown
        if alert_key in self.alert_cooldown:
            if time.time() - self.alert_cooldown[alert_key] < self.cooldown_period:
                return False
        
        # Update cooldown
        self.alert_cooldown[alert_key] = time.time()
        
        # Track active alert
        self.active_alerts.add(alert_key)
        
        return True
    
    async def _send_alert(self, severity: str, title: str, 
                         message: str, details: dict):
        """Send an alert through configured channels.
        
        Args:
            severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
            title: Alert title
            message: Alert message
            details: Additional details
        """
        try:
            alert_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": severity,
                "title": title,
                "message": message,
                "details": details
            }
            
            # Store alert in Redis
            await self.redis.lpush(
                "alerts:history",
                json.dumps(alert_data)
            )
            await self.redis.ltrim("alerts:history", 0, 999)  # Keep last 1000
            
            # Store by severity
            await self.redis.lpush(
                f"alerts:{severity.lower()}",
                json.dumps(alert_data)
            )
            await self.redis.ltrim(f"alerts:{severity.lower()}", 0, 99)
            
            # Update alert counts
            current_hour = datetime.now(timezone.utc).strftime("%Y%m%d:%H")
            await self.redis.hincrby(f"alerts:counts:{current_hour}", severity, 1)
            await self.redis.expire(f"alerts:counts:{current_hour}", 86400)  # 24 hours
            
            # Send to webhook if configured
            if self.webhook_url:
                await self._send_webhook(alert_data)
            
            # Log the alert
            logger.warning(f"ALERT [{severity}] {title}: {message}")
            
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
    
    async def _send_webhook(self, alert_data: dict):
        """Send alert to webhook URL.
        
        Args:
            alert_data: Alert data to send
        """
        # This would use httpx or similar to POST to webhook
        # Implementation depends on webhook format requirements
        pass
    
    async def handle_unknown(self, stream: str, msg_id: str, data: dict):
        """Handle messages with no matching handler.
        
        Args:
            stream: Stream the message came from
            msg_id: Message ID
            data: Parsed message data
        """
        # Log unknown message types for debugging
        event_type = data.get("event_type") or data.get("type") or "unknown"
        logger.debug(f"No handler for event type: {event_type}")
    
    async def get_alert_summary(self) -> dict:
        """Get summary of alerts.
        
        Returns:
            Dictionary with alert statistics
        """
        current_hour = datetime.now(timezone.utc).strftime("%Y%m%d:%H")
        
        # Get alert counts
        counts = await self.redis.hgetall(f"alerts:counts:{current_hour}")
        
        # Get active alerts count
        active_count = len(self.active_alerts)
        
        # Get recent alerts
        recent = await self.redis.lrange("alerts:history", 0, 9)
        recent_alerts = [json.loads(alert) for alert in recent]
        
        return {
            "hourly_counts": {k: int(v) for k, v in counts.items()},
            "active_alerts": active_count,
            "recent_alerts": recent_alerts,
            "error_components": list(self.error_counts.keys()),
            "slow_hostnames": [
                hostname for hostname, times in self.response_times.items()
                if times and sum(times) / len(times) > self.response_time_threshold / 2
            ]
        }