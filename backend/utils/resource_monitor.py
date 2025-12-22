import psutil
import logging
import asyncio
import time
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass
from datetime import datetime
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

@dataclass
class ResourceMetrics:
    """Resource usage metrics."""
    cpu_percent: float
    memory_mb: float
    network_connections: int
    timestamp: datetime
    disk_io_read: float = 0.0
    disk_io_write: float = 0.0
    network_io_sent: float = 0.0
    network_io_recv: float = 0.0

class ResourceMonitor:
    """Monitors system resource usage and enforces limits."""
    
    def __init__(self, resource_limits: Dict[str, Any]):
        self.resource_limits = resource_limits
        self._monitoring_task: Optional[asyncio.Task] = None
        self._metrics_history: List[ResourceMetrics] = []
        self._max_history_size = 1000
        self._process = psutil.Process()
        self._last_io_counters = None
        self._last_net_counters = None
        self._last_check_time = None
        self._active_monitors: Set[str] = set()
        self._stop_event = asyncio.Event()
    
    async def start_monitoring(self, interval: float = 1.0):
        """Start resource monitoring."""
        if self._monitoring_task is not None:
            logger.warning("Resource monitoring is already running")
            return

        self._stop_event.clear()
        self._monitoring_task = asyncio.create_task(
            self._monitor_resources(interval)
        )
        logger.info("Resource monitoring started")
    
    async def stop_monitoring(self):
        """Stop resource monitoring and cleanup resources."""
        if self._monitoring_task is None:
            return

        self._stop_event.set()
        try:
            await asyncio.wait_for(self._monitoring_task, timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("Resource monitoring task did not stop gracefully")
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass

        self._monitoring_task = None
        self._metrics_history.clear()
        self._active_monitors.clear()
        logger.info("Resource monitoring stopped")
    
    @asynccontextmanager
    async def monitor_scope(self, monitor_id: str):
        """Context manager for monitoring a specific operation."""
        try:
            self._active_monitors.add(monitor_id)
            yield
        finally:
            self._active_monitors.remove(monitor_id)
    
    async def _monitor_resources(self, interval: float):
        """Monitor system resources at regular intervals."""
        try:
            while not self._stop_event.is_set():
                try:
                    metrics = self._collect_metrics()
                    self._metrics_history.append(metrics)
                    
                    # Trim history if it gets too large
                    if len(self._metrics_history) > self._max_history_size:
                        self._metrics_history = self._metrics_history[-self._max_history_size:]
                    
                    # Check resource limits (only log if exceeded)
                    if self._check_resource_limits(metrics):
                        logger.warning(f"Resource limits exceeded - CPU: {metrics.cpu_percent:.1f}%, Memory: {metrics.memory_mb:.1f}MB, Connections: {metrics.network_connections}")
                    
                    await asyncio.sleep(interval)
                except Exception as e:
                    logger.error(f"Error collecting metrics: {e}")
                    await asyncio.sleep(interval)  # Continue monitoring even if one collection fails
        except Exception as e:
            logger.error(f"Error in resource monitoring: {e}", exc_info=True)
            raise
    
    def _collect_metrics(self) -> ResourceMetrics:
        """Collect current resource usage metrics."""
        current_time = datetime.now()
        
        try:
            # Get CPU and memory metrics (with error handling)
            cpu_percent = self._process.cpu_percent()
            memory_info = self._process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)  # Convert to MB
            
            # Get network connections (with error handling)
            try:
                network_connections = len(self._process.connections())
            except (psutil.AccessDenied, psutil.ZombieProcess):
                network_connections = 0
            
            # Get I/O metrics (with error handling)
            try:
                io_counters = psutil.disk_io_counters()
                net_counters = psutil.net_io_counters()
            except (psutil.AccessDenied, AttributeError):
                io_counters = None
                net_counters = None
            
            # Calculate I/O rates
            disk_io_read = 0.0
            disk_io_write = 0.0
            network_io_sent = 0.0
            network_io_recv = 0.0
            
            if (self._last_io_counters and self._last_net_counters and 
                self._last_check_time and io_counters and net_counters):
                time_diff = (current_time - self._last_check_time).total_seconds()
                if time_diff > 0:
                    disk_io_read = (io_counters.read_bytes - self._last_io_counters.read_bytes) / time_diff
                    disk_io_write = (io_counters.write_bytes - self._last_io_counters.write_bytes) / time_diff
                    network_io_sent = (net_counters.bytes_sent - self._last_net_counters.bytes_sent) / time_diff
                    network_io_recv = (net_counters.bytes_recv - self._last_net_counters.bytes_recv) / time_diff
            
            # Update last values
            self._last_io_counters = io_counters
            self._last_net_counters = net_counters
            self._last_check_time = current_time
            
            return ResourceMetrics(
                cpu_percent=cpu_percent,
                memory_mb=memory_mb,
                network_connections=network_connections,
                timestamp=current_time,
                disk_io_read=disk_io_read,
                disk_io_write=disk_io_write,
                network_io_sent=network_io_sent,
                network_io_recv=network_io_recv
            )
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            # Return minimal metrics on error
            return ResourceMetrics(
                cpu_percent=0.0,
                memory_mb=0.0,
                network_connections=0,
                timestamp=current_time
            )
    
    def _check_resource_limits(self, metrics: ResourceMetrics) -> bool:
        """Check if current resource usage exceeds limits."""
        return (
            metrics.cpu_percent > self.resource_limits['max_cpu_percent'] or
            metrics.memory_mb > self.resource_limits['max_memory_mb'] or
            metrics.network_connections > self.resource_limits['max_network_connections']
        )
    
    def check_resource_availability(self) -> bool:
        """Check if resources are currently available based on defined limits."""
        metrics = self.get_current_metrics()
        if not metrics:
            # If no metrics are available yet, assume resources are available
            return True
        return not self._check_resource_limits(metrics)
    
    def get_current_metrics(self) -> Optional[ResourceMetrics]:
        """Get the most recent resource metrics."""
        return self._metrics_history[-1] if self._metrics_history else None
    
    def get_metrics_history(self) -> List[ResourceMetrics]:
        """Get the history of resource metrics."""
        return self._metrics_history.copy()
    
    def clear_history(self):
        """Clear the metrics history."""
        self._metrics_history.clear()

    def get_active_monitors(self) -> Set[str]:
        """Get the set of currently active monitor IDs."""
        return self._active_monitors.copy()

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start_monitoring()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop_monitoring() 
