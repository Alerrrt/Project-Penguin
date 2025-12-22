import logging
import logging.handlers
import os
import json
import sys
from datetime import datetime
from typing import Any, Dict

class StructuredLogFormatter(logging.Formatter):
    """Formatter for structured JSON logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process_id": record.process,
            "thread_id": record.thread,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }

        # Add extra fields if present
        if hasattr(record, "extra"):
            log_data.update(record.extra)

        return json.dumps(log_data)

class ErrorLogFilter(logging.Filter):
    """Filter for error logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter log records based on level."""
        return record.levelno >= logging.ERROR

def setup_logging(
    log_level: str = "INFO",
    log_dir: str = "logs",
    app_name: str = "security_scanner"
) -> None:
    """
    Set up logging configuration.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files
        app_name: Application name for log files
    """
    # Set up logging with UTF-8 encoding
    logging.basicConfig(
        encoding='utf-8',
        level=log_level.upper(),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)

    # Convert string log level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear existing handlers
    root_logger.handlers = []

    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    root_logger.addHandler(console_handler)

    # Add file handlers
    handlers = [
        logging.handlers.RotatingFileHandler(
            filename=os.path.join(log_dir, f"{app_name}.log"),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        ),
        logging.handlers.RotatingFileHandler(
            filename=os.path.join(log_dir, f"{app_name}_error.log"),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        )
    ]
    
    for handler in handlers:
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        if hasattr(handler, 'baseFilename') and handler.baseFilename.endswith('_error.log'):
            handler.addFilter(ErrorLogFilter())
        root_logger.addHandler(handler)

    # Set logging levels for specific modules
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    # Add filter for Unicode characters
    class UnicodeEncodeFilter(logging.Filter):
        def filter(self, record):
            try:
                record.msg = record.msg.encode('utf-8').decode('latin-1')
                return True
            except (UnicodeEncodeError, UnicodeDecodeError):
                return False

    root_logger.addFilter(UnicodeEncodeFilter())

    # Log startup message
    logging.info(
        "Logging initialized",
        extra={
            "log_level": log_level,
            "log_dir": log_dir,
            "app_name": app_name
        }
    )

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)

class LoggerAdapter(logging.LoggerAdapter):
    """Logger adapter for adding context to log messages."""

    def __init__(self, logger: logging.Logger, extra: Dict[str, Any]):
        super().__init__(logger, extra or {})

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        """Process the log message and kwargs."""
        if "extra" not in kwargs:
            kwargs["extra"] = {}
        kwargs["extra"].update(self.extra)
        return msg, kwargs

def get_context_logger(name: str, **context) -> LoggerAdapter:
    """
    Get a logger with context.
    
    Args:
        name: Logger name
        **context: Context variables to include in log messages
        
    Returns:
        LoggerAdapter instance
    """
    logger = get_logger(name)
    return LoggerAdapter(logger, context) 
