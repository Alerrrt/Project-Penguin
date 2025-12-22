# -*- coding: utf-8 -*-
import asyncio
import logging
import time
import random # For jitter
from enum import Enum
from typing import Optional, Callable, Any, Dict
from functools import wraps

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"      # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service is recovered

class CircuitBreaker:
    """
    Circuit breaker implementation for handling failures gracefully.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_timeout: float = 5.0,
        name: str = "default",
        # Exponential backoff parameters
        base_delay: float = 1.0,  # Base delay for exponential backoff
        max_delay: float = 30.0,  # Max delay for exponential backoff
        jitter_percent: float = 0.2  # Jitter percentage
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_timeout = half_open_timeout
        self.name = name
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_start_time: Optional[float] = None
        self._success_count = 0
        self._lock = asyncio.Lock()
        
        # Exponential backoff properties
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._jitter_percent = jitter_percent
        self._current_recovery_delay = recovery_timeout # Dynamic recovery delay

        # Statistics
        self._total_requests = 0
        self._total_failures = 0
        self._total_successes = 0
        self._total_rejections = 0

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        return self._failure_count

    @property
    def success_count(self) -> int:
        """Get current success count."""
        return self._success_count

    @property
    def statistics(self) -> Dict[str, Any]: # Changed to Any for dynamic types like float
        """Get circuit breaker statistics."""
        return {
            "total_requests": self._total_requests,
            "total_failures": self._total_failures,
            "total_successes": self._total_successes,
            "total_rejections": self._total_rejections,
            "current_failures": self._failure_count,
            "current_successes": self._success_count,
            "current_recovery_delay": self._current_recovery_delay # Add current delay to stats
        }

    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute a function with circuit breaker protection.
        
        Args:
            func: The async function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            The result of the function execution
            
        Raises:
            CircuitBreakerOpenError: If the circuit is open
            Exception: The original exception from the function
        """
        self._total_requests += 1
        
        # Check if request is allowed based on current state and timeout
        if not await self._allow_request():
            self._total_rejections += 1
            raise CircuitBreakerOpenError(
                f"Circuit breaker '{self.name}' is open. "
                f"Last failure: {self._last_failure_time} (next retry in approx {self._current_recovery_delay - (time.time() - (self._last_failure_time if self._last_failure_time else 0)):.2f}s)"
            )

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure()
            raise

    async def _allow_request(self) -> bool:
        """
        Check if a request should be allowed based on circuit state.
        """
        async with self._lock:
            current_time = time.time()
            
            if self._state == CircuitState.CLOSED:
                return True
                
            if self._state == CircuitState.OPEN:
                if self._last_failure_time is None or current_time - self._last_failure_time >= self._current_recovery_delay:
                    logger.info(f"Circuit '{self.name}' transitioning to half-open after {self._current_recovery_delay:.2f}s delay.")
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_start_time = current_time
                    self._success_count = 0 # Reset success count for half-open test
                    return True
                return False
                
            if self._state == CircuitState.HALF_OPEN:
                # In half-open, we allow a test request. If it succeeds, we close. If it fails, we open.
                # The half_open_timeout isn't for blocking requests, but for how long we stay in HALF_OPEN
                # before potentially returning to CLOSED if multiple successes are needed.
                return True

    async def _on_success(self):
        """
        Handle successful execution.
        """
        async with self._lock:
            self._total_successes += 1
            self._success_count += 1
            
            if self._state == CircuitState.HALF_OPEN:
                # If we get a success in half-open, we can close the circuit
                logger.info(f"Circuit '{self.name}' transitioning to closed after success in half-open.")
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._success_count = 0
                self._current_recovery_delay = self.recovery_timeout # Reset delay on success
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0 # Reset failures on success in closed state
                self._current_recovery_delay = self.recovery_timeout # Reset delay on success

    async def _on_failure(self):
        """
        Handle execution failure.
        """
        async with self._lock:
            self._total_failures += 1
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            # Fixed logic for state transition
            if (self._state == CircuitState.HALF_OPEN) or \
               (self._state == CircuitState.CLOSED and self._failure_count >= self.failure_threshold):
                logger.warning(f"Circuit '{self.name}' transitioning to open. Failures: {self._failure_count}/{self.failure_threshold}")
                self._state = CircuitState.OPEN
                self._success_count = 0 # Reset success count
                
                # Apply exponential backoff with jitter
                self._current_recovery_delay = min(
                    self._max_delay,
                    self._current_recovery_delay * 2 # Exponential increase
                )
                jitter = self._current_recovery_delay * self._jitter_percent
                self._current_recovery_delay += random.uniform(-jitter, jitter)
                self._current_recovery_delay = max(self._base_delay, self._current_recovery_delay) # Ensure minimum delay

    def reset(self):
        """
        Reset the circuit breaker to initial state.
        """
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None
        self._half_open_start_time = None
        self._total_requests = 0
        self._total_failures = 0
        self._total_successes = 0
        self._total_rejections = 0
        self._current_recovery_delay = self.recovery_timeout # Reset dynamic delay

class CircuitBreakerOpenError(Exception):
    """Custom exception for when the circuit breaker is open."""
    pass

def circuit_breaker(
    failure_threshold: int = 3, # Adjusted default to match test case
    recovery_timeout: float = 10.0, # Adjusted default to match test case
    half_open_timeout: float = 5.0,
    name: Optional[str] = None,
    # New parameters for exponential backoff in decorator
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter_percent: float = 0.2
):
    """
    Decorator for applying circuit breaker pattern to async functions.
    
    Args:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Time in seconds before attempting recovery
        half_open_timeout: Time in seconds to test recovery
        name: Optional name for the circuit breaker
        base_delay: Base delay for exponential backoff
        max_delay: Max delay for exponential backoff
        jitter_percent: Jitter percentage for backoff
    """
    def decorator(func):
        cb = CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            half_open_timeout=half_open_timeout,
            name=name or func.__name__,
            base_delay=base_delay,
            max_delay=max_delay,
            jitter_percent=jitter_percent
        )
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await cb.execute(func, *args, **kwargs)
            
        wrapper.circuit_breaker = cb
        return wrapper
    
    return decorator
