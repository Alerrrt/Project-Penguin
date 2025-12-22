import logging
import traceback
from typing import Optional, Dict, Any
from datetime import datetime
from functools import wraps
import sys
from backend.utils.logging_config import get_context_logger

logger = get_context_logger(__name__)

class ErrorHandler:
    def __init__(self):
        self.error_counts: Dict[str, int] = {}
        self.last_errors: Dict[str, Dict[str, Any]] = {}
        self.error_threshold = 10  # Maximum number of errors before taking action
        self.error_window = 300  # Time window in seconds for error counting

    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        severity: str = "ERROR",
        retry: bool = False
    ) -> Dict[str, Any]:
        """
        Handle an error with context and severity level.
        
        Args:
            error: The exception that occurred
            context: Additional context about the error
            severity: Error severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            retry: Whether the operation should be retried
            
        Returns:
            Dict containing error details and handling result
        """
        error_type = type(error).__name__
        error_time = datetime.now()
        
        # Update error counts
        if error_type not in self.error_counts:
            self.error_counts[error_type] = 0
        self.error_counts[error_type] += 1
        
        # Store last error
        self.last_errors[error_type] = {
            "error": str(error),
            "timestamp": error_time,
            "context": context or {},
            "traceback": traceback.format_exc()
        }
        
        # Log error with context
        log_message = f"Error: {error_type} - {str(error)}"
        if context:
            log_message += f" Context: {context}"
        
        if severity == "CRITICAL":
            logger.critical(log_message, exc_info=True, extra=context)
        elif severity == "ERROR":
            logger.error(log_message, exc_info=True, extra=context)
        elif severity == "WARNING":
            logger.warning(log_message, extra=context)
        elif severity == "INFO":
            logger.info(log_message, extra=context)
        else:
            logger.debug(log_message, extra=context)
        
        # Check if error threshold exceeded
        if self.error_counts[error_type] >= self.error_threshold:
            self._handle_error_threshold_exceeded(error_type)
        
        return {
            "error_type": error_type,
            "message": str(error),
            "timestamp": error_time.isoformat(),
            "context": context,
            "retry": retry,
            "severity": severity
        }

    def _handle_error_threshold_exceeded(self, error_type: str):
        """Handle cases where error threshold is exceeded."""
        logger.critical(
            f"Error threshold exceeded for {error_type}",
            extra={
                "error_type": error_type,
                "count": self.error_counts[error_type],
                "last_error": self.last_errors[error_type]
            }
        )
        
        # Implement your error threshold handling logic here
        # For example, notify administrators, restart services, etc.

    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics."""
        return {
            "error_counts": self.error_counts,
            "last_errors": {
                error_type: {
                    "message": error_data["error"],
                    "timestamp": error_data["timestamp"].isoformat(),
                    "context": error_data["context"]
                }
                for error_type, error_data in self.last_errors.items()
            }
        }

    def reset_error_counts(self):
        """Reset error counts."""
        self.error_counts.clear()
        self.last_errors.clear()

# Global error handler instance
error_handler = ErrorHandler()

def handle_exceptions(func):
    """
    Decorator for handling exceptions in functions.
    
    Usage:
    @handle_exceptions
    def your_function():
        # Your code here
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            context = {
                "function": func.__name__,
                "args": str(args),
                "kwargs": str(kwargs)
            }
            return error_handler.handle_error(e, context)
    return wrapper

def log_execution_time(func):
    """
    Decorator for logging function execution time.
    
    Usage:
    @log_execution_time
    def your_function():
        # Your code here
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = datetime.now()
        try:
            result = await func(*args, **kwargs)
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.debug(
                f"Function {func.__name__} executed in {execution_time:.2f} seconds",
                extra={
                    "function": func.__name__,
                    "execution_time": execution_time
                }
            )
            return result
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.error(
                f"Function {func.__name__} failed after {execution_time:.2f} seconds",
                exc_info=True,
                extra={
                    "function": func.__name__,
                    "execution_time": execution_time
                }
            )
            raise
    return wrapper

def monitor_resources(func):
    """
    Decorator for monitoring resource usage during function execution.
    
    Usage:
    @monitor_resources
    def your_function():
        # Your code here
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        import psutil
        process = psutil.Process()
        
        # Get initial resource usage
        initial_cpu = process.cpu_percent()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        try:
            result = await func(*args, **kwargs)
            
            # Get final resource usage
            final_cpu = process.cpu_percent()
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            # Log resource usage
            logger.debug(
                f"Resource usage for {func.__name__}",
                extra={
                    "function": func.__name__,
                    "cpu_usage": final_cpu - initial_cpu,
                    "memory_usage": final_memory - initial_memory
                }
            )
            
            return result
        except Exception as e:
            # Log resource usage on error
            final_cpu = process.cpu_percent()
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            logger.error(
                f"Resource usage on error for {func.__name__}",
                exc_info=True,
                extra={
                    "function": func.__name__,
                    "cpu_usage": final_cpu - initial_cpu,
                    "memory_usage": final_memory - initial_memory
                }
            )
            raise
    return wrapper

# Export the error handler instance
def get_error_handler() -> ErrorHandler:
    return error_handler 
