"""Main orchestrator for unified async Redis Streams architecture.

This module initializes and coordinates all async components with
comprehensive event publishing and trace correlation.
"""

import asyncio
import logging
import os
import signal
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from ..storage.redis_clients import RedisClients, initialize_redis_clients
from ..storage.async_redis_storage import AsyncRedisStorage
from ..ports.async_manager import AsyncPortManager
from ..docker.async_manager import AsyncDockerManager
from ..certmanager.async_manager import AsyncCertificateManager
from ..proxy.async_handler import EnhancedAsyncProxyHandler
from ..consumers.metrics_processor import MetricsProcessor
from ..consumers.alert_manager import AlertManager
from ..shared.unified_logger import UnifiedAsyncLogger
from ..shared.config import Config

logger = logging.getLogger(__name__)


class MainOrchestrator:
    """Orchestrates all async components with unified logging and events."""
    
    def __init__(self):
        """Initialize the orchestrator."""
        self.redis_clients: Optional[RedisClients] = None
        self.async_storage: Optional[AsyncRedisStorage] = None
        self.logger: Optional[UnifiedAsyncLogger] = None
        
        # Managers
        self.port_manager: Optional[AsyncPortManager] = None
        self.docker_manager: Optional[AsyncDockerManager] = None
        self.cert_manager: Optional[AsyncCertificateManager] = None
        self.proxy_handler: Optional[EnhancedAsyncProxyHandler] = None
        
        # Consumers
        self.metrics_processor: Optional[MetricsProcessor] = None
        self.alert_manager: Optional[AlertManager] = None
        
        # Control
        self.running = False
        self.shutdown_event = asyncio.Event()
    
    async def initialize(self) -> None:
        """Initialize all components with proper async setup."""
        start_time = datetime.now(timezone.utc)
        
        try:
            logger.info("Initializing Main Orchestrator...")
            
            # Initialize Redis clients
            logger.info("Initializing Redis clients...")
            self.redis_clients = await initialize_redis_clients()
            
            # Initialize async storage
            logger.info("Initializing async storage...")
            self.async_storage = AsyncRedisStorage(Config.REDIS_URL)
            await self.async_storage.initialize()
            
            # Initialize unified logger
            logger.info("Initializing unified logger...")
            self.logger = UnifiedAsyncLogger(self.redis_clients)
            self.logger.set_component("orchestrator")
            
            # Start initialization trace
            trace_id = self.logger.start_trace(
                "orchestrator_initialization",
                start_time=start_time.isoformat()
            )
            
            try:
                # Initialize managers
                await self._initialize_managers(trace_id)
                
                # Initialize consumers
                await self._initialize_consumers(trace_id)
                
                # Perform health checks
                await self._perform_health_checks(trace_id)
                
                # Calculate initialization time
                init_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                
                await self.logger.info(
                    f"Orchestrator initialized successfully in {init_duration:.2f}s",
                    trace_id=trace_id
                )
                
                # Publish initialization complete event
                await self.logger.event(
                    "orchestrator_initialized",
                    {
                        "duration_seconds": init_duration,
                        "components": {
                            "redis_clients": "initialized",
                            "async_storage": "initialized",
                            "port_manager": "initialized",
                            "docker_manager": "initialized",
                            "cert_manager": "initialized",
                            "proxy_handler": "initialized",
                            "metrics_processor": "initialized",
                            "alert_manager": "initialized"
                        }
                    },
                    trace_id=trace_id
                )
                
                await self.logger.end_trace(trace_id, "success", duration_seconds=init_duration)
                
                logger.info(f"Main Orchestrator initialized in {init_duration:.2f} seconds")
                
            except Exception as e:
                await self.logger.error(
                    f"Orchestrator initialization failed: {str(e)}",
                    trace_id=trace_id,
                    error_type=type(e).__name__
                )
                await self.logger.end_trace(trace_id, "error", error=str(e))
                raise
                
        except Exception as e:
            logger.error(f"Failed to initialize orchestrator: {e}")
            raise
    
    async def _initialize_managers(self, trace_id: str) -> None:
        """Initialize all manager components.
        
        Args:
            trace_id: Trace ID for correlation
        """
        self.logger.add_span(trace_id, "initialize_managers")
        
        # Initialize port manager
        await self.logger.debug("Initializing port manager...", trace_id=trace_id)
        self.port_manager = AsyncPortManager(self.async_storage)
        
        # Initialize Docker manager
        await self.logger.debug("Initializing Docker manager...", trace_id=trace_id)
        self.docker_manager = AsyncDockerManager(self.async_storage, self.redis_clients)
        
        # Initialize certificate manager
        await self.logger.debug("Initializing certificate manager...", trace_id=trace_id)
        self.cert_manager = AsyncCertificateManager(self.async_storage, self.redis_clients)
        
        # Initialize proxy handler
        await self.logger.debug("Initializing proxy handler...", trace_id=trace_id)
        self.proxy_handler = EnhancedAsyncProxyHandler(self.async_storage, self.redis_clients)
        
        await self.logger.info(
            "All managers initialized",
            trace_id=trace_id
        )
    
    async def _initialize_consumers(self, trace_id: str) -> None:
        """Initialize and start stream consumers.
        
        Args:
            trace_id: Trace ID for correlation
        """
        self.logger.add_span(trace_id, "initialize_consumers")
        
        # Initialize metrics processor
        await self.logger.debug("Initializing metrics processor...", trace_id=trace_id)
        self.metrics_processor = MetricsProcessor(self.redis_clients.stream_redis)
        
        # Initialize alert manager
        await self.logger.debug("Initializing alert manager...", trace_id=trace_id)
        self.alert_manager = AlertManager(self.redis_clients.stream_redis)
        
        # Start consumers
        await self.logger.debug("Starting consumers...", trace_id=trace_id)
        await self.metrics_processor.start()
        await self.alert_manager.start()
        
        await self.logger.info(
            "All consumers started",
            trace_id=trace_id
        )
    
    async def _perform_health_checks(self, trace_id: str) -> None:
        """Perform health checks on all components.
        
        Args:
            trace_id: Trace ID for correlation
        """
        self.logger.add_span(trace_id, "health_checks")
        
        health_status = {}
        
        # Check Redis connectivity
        try:
            await self.redis_clients.async_redis.ping()
            health_status["redis_async"] = "healthy"
        except Exception as e:
            health_status["redis_async"] = f"unhealthy: {e}"
        
        try:
            await self.redis_clients.stream_redis.ping()
            health_status["redis_stream"] = "healthy"
        except Exception as e:
            health_status["redis_stream"] = f"unhealthy: {e}"
        
        # Check consumer lag
        try:
            metrics_lag = await self.metrics_processor.get_lag()
            alert_lag = await self.alert_manager.get_lag()
            
            max_metrics_lag = max(metrics_lag.values()) if metrics_lag else 0
            max_alert_lag = max(alert_lag.values()) if alert_lag else 0
            
            health_status["metrics_consumer_lag"] = max_metrics_lag
            health_status["alert_consumer_lag"] = max_alert_lag
            
            if max_metrics_lag > 1000:
                await self.logger.warning(
                    f"High metrics consumer lag: {max_metrics_lag}",
                    trace_id=trace_id
                )
            
            if max_alert_lag > 1000:
                await self.logger.warning(
                    f"High alert consumer lag: {max_alert_lag}",
                    trace_id=trace_id
                )
        except Exception as e:
            health_status["consumer_lag"] = f"check failed: {e}"
        
        await self.logger.debug(
            "Health checks completed",
            trace_id=trace_id,
            health_status=health_status
        )
    
    async def start(self) -> None:
        """Start the orchestrator and all components."""
        if self.running:
            logger.warning("Orchestrator already running")
            return
        
        self.running = True
        
        trace_id = self.logger.start_trace("orchestrator_start")
        
        try:
            await self.logger.info(
                "Starting orchestrator services...",
                trace_id=trace_id
            )
            
            # Start certificate manager auto-renewal
            await self.cert_manager.start()
            
            # Publish started event
            await self.logger.event(
                "orchestrator_started",
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "pid": os.getpid()
                },
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "success")
            
            logger.info("Orchestrator started successfully")
            
        except Exception as e:
            await self.logger.error(
                f"Failed to start orchestrator: {str(e)}",
                trace_id=trace_id
            )
            await self.logger.end_trace(trace_id, "error", error=str(e))
            self.running = False
            raise
    
    async def stop(self) -> None:
        """Stop the orchestrator and cleanup."""
        if not self.running:
            logger.warning("Orchestrator not running")
            return
        
        trace_id = self.logger.start_trace("orchestrator_shutdown")
        
        try:
            await self.logger.info(
                "Stopping orchestrator services...",
                trace_id=trace_id
            )
            
            self.running = False
            
            # Stop certificate manager
            if self.cert_manager:
                await self.cert_manager.stop()
            
            # Stop consumers
            if self.metrics_processor:
                await self.metrics_processor.stop()
            
            if self.alert_manager:
                await self.alert_manager.stop()
            
            # Close proxy handler
            if self.proxy_handler:
                await self.proxy_handler.close()
            
            # Flush logs
            if self.logger:
                await self.logger.flush()
            
            # Close storage
            if self.async_storage:
                await self.async_storage.close()
            
            # Close Redis clients
            if self.redis_clients:
                await self.redis_clients.close()
            
            await self.logger.event(
                "orchestrator_stopped",
                {
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "success")
            
            logger.info("Orchestrator stopped successfully")
            
        except Exception as e:
            if self.logger:
                await self.logger.error(
                    f"Error during orchestrator shutdown: {str(e)}",
                    trace_id=trace_id
                )
                await self.logger.end_trace(trace_id, "error", error=str(e))
            logger.error(f"Error during orchestrator shutdown: {e}")
    
    async def run(self) -> None:
        """Run the orchestrator until shutdown signal."""
        await self.start()
        
        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(
                sig,
                lambda: asyncio.create_task(self.handle_shutdown())
            )
        
        # Wait for shutdown
        await self.shutdown_event.wait()
        
        # Stop services
        await self.stop()
    
    async def handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        logger.info("Received shutdown signal")
        self.shutdown_event.set()
    
    async def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status.
        
        Returns:
            Status dictionary
        """
        status = {
            "running": self.running,
            "components": {}
        }
        
        if self.redis_clients:
            try:
                await self.redis_clients.async_redis.ping()
                status["components"]["redis"] = "connected"
            except:
                status["components"]["redis"] = "disconnected"
        
        if self.metrics_processor:
            lag = await self.metrics_processor.get_lag()
            status["components"]["metrics_processor"] = {
                "running": self.metrics_processor.running,
                "lag": max(lag.values()) if lag else 0
            }
        
        if self.alert_manager:
            lag = await self.alert_manager.get_lag()
            alerts = await self.alert_manager.get_alert_summary()
            status["components"]["alert_manager"] = {
                "running": self.alert_manager.running,
                "lag": max(lag.values()) if lag else 0,
                "active_alerts": alerts.get("active_alerts", 0)
            }
        
        if self.cert_manager:
            status["components"]["cert_manager"] = {
                "running": self.cert_manager.running,
                "renewal_enabled": self.cert_manager.renewal_task is not None
            }
        
        return status


async def create_orchestrator() -> MainOrchestrator:
    """Create and initialize the main orchestrator.
    
    Returns:
        Initialized orchestrator instance
    """
    orchestrator = MainOrchestrator()
    await orchestrator.initialize()
    return orchestrator


async def run_orchestrator() -> None:
    """Run the orchestrator as the main application."""
    orchestrator = await create_orchestrator()
    await orchestrator.run()