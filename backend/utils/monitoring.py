import logging
import psutil
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import deque
import json
from backend.utils.logging_config import get_context_logger
from backend.utils.error_handler import get_error_handler

logger = get_context_logger(__name__)

class SystemMonitor:
    def __init__(self, history_size: int = 1000):
        """
        Initialize system monitor.
        
        Args:
            history_size: Number of historical metrics to keep
        """
        self.history_size = history_size
        self.metrics_history = {
            "cpu": deque(maxlen=history_size),
            "memory": deque(maxlen=history_size),
            "disk": deque(maxlen=history_size),
            "network": deque(maxlen=history_size),
            "process": deque(maxlen=history_size)
        }
        self.alerts: List[Dict] = []
        self.monitoring_task: Optional[asyncio.Task] = None
        self.error_handler = get_error_handler()

    async def start_monitoring(self, interval: int = 60):
        """
        Start system monitoring.
        
        Args:
            interval: Monitoring interval in seconds
        """
        if self.monitoring_task is not None:
            return

        self.monitoring_task = asyncio.create_task(
            self._monitoring_loop(interval)
        )
        logger.info("System monitoring started")

    async def stop_monitoring(self):
        """Stop system monitoring."""
        if self.monitoring_task is not None:
            self.monitoring_task.cancel()
            self.monitoring_task = None
            logger.info("System monitoring stopped")

    async def _monitoring_loop(self, interval: int):
        """Main monitoring loop."""
        while True:
            try:
                metrics = await self._collect_metrics()
                self._update_history(metrics)
                self._check_alerts(metrics)
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.error_handler.handle_error(
                    e,
                    context={"component": "system_monitor"},
                    severity="ERROR"
                )
                await asyncio.sleep(interval)

    async def _collect_metrics(self) -> Dict:
        """Collect system metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            net_io = psutil.net_io_counters()
            
            # Process metrics
            process = psutil.Process()
            process_cpu = process.cpu_percent()
            process_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            return {
                "timestamp": datetime.now().isoformat(),
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "frequency": {
                        "current": cpu_freq.current,
                        "min": cpu_freq.min,
                        "max": cpu_freq.max
                    }
                },
                "memory": {
                    "total": memory.total / 1024 / 1024,  # MB
                    "available": memory.available / 1024 / 1024,  # MB
                    "percent": memory.percent
                },
                "disk": {
                    "total": disk.total / 1024 / 1024,  # MB
                    "used": disk.used / 1024 / 1024,  # MB
                    "free": disk.free / 1024 / 1024,  # MB
                    "percent": disk.percent
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                },
                "process": {
                    "cpu_percent": process_cpu,
                    "memory_mb": process_memory,
                    "threads": process.num_threads(),
                    "open_files": len(process.open_files()),
                    "connections": len(process.connections())
                }
            }
        except Exception as e:
            self.error_handler.handle_error(
                e,
                context={"component": "metrics_collection"},
                severity="ERROR"
            )
            return {}

    def _update_history(self, metrics: Dict):
        """Update metrics history."""
        for category in self.metrics_history:
            if category in metrics:
                self.metrics_history[category].append(metrics[category])

    def _check_alerts(self, metrics: Dict):
        """Check for alert conditions."""
        # CPU alert
        if metrics.get("cpu", {}).get("percent", 0) > 80:
            self._create_alert("high_cpu", metrics["cpu"])

        # Memory alert
        if metrics.get("memory", {}).get("percent", 0) > 80:
            self._create_alert("high_memory", metrics["memory"])

        # Disk alert
        if metrics.get("disk", {}).get("percent", 0) > 80:
            self._create_alert("low_disk_space", metrics["disk"])

        # Process alert
        if metrics.get("process", {}).get("memory_mb", 0) > 1000:  # 1GB
            self._create_alert("high_process_memory", metrics["process"])

    def _create_alert(self, alert_type: str, data: Dict):
        """Create a new alert."""
        alert = {
            "type": alert_type,
            "timestamp": datetime.now().isoformat(),
            "data": data
        }
        self.alerts.append(alert)
        logger.warning(f"Alert created: {alert_type}", extra=alert)

    def get_metrics_history(self, category: Optional[str] = None) -> Dict:
        """Get metrics history."""
        if category:
            return {
                category: list(self.metrics_history.get(category, []))
            }
        return {
            cat: list(metrics)
            for cat, metrics in self.metrics_history.items()
        }

    def get_alerts(self, 
                  start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None,
                  alert_type: Optional[str] = None) -> List[Dict]:
        """Get filtered alerts."""
        filtered_alerts = self.alerts
        
        if start_time:
            filtered_alerts = [
                alert for alert in filtered_alerts
                if datetime.fromisoformat(alert["timestamp"]) >= start_time
            ]
        
        if end_time:
            filtered_alerts = [
                alert for alert in filtered_alerts
                if datetime.fromisoformat(alert["timestamp"]) <= end_time
            ]
        
        if alert_type:
            filtered_alerts = [
                alert for alert in filtered_alerts
                if alert["type"] == alert_type
            ]
        
        return filtered_alerts

    def clear_alerts(self):
        """Clear all alerts."""
        self.alerts.clear()

# Global monitor instance
system_monitor = SystemMonitor()

# Export the monitor instance
def get_system_monitor() -> SystemMonitor:
    return system_monitor 
