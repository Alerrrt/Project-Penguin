from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

class ScannerIntensity(str, Enum):
    """Resource intensity levels for scanners."""
    LIGHT = "light"
    MEDIUM = "medium"
    HEAVY = "heavy"

class ScannerConfig(BaseModel):
    """Base configuration for a scanner."""
    enabled: bool = Field(True, description="Whether the scanner is enabled")
    timeout: int = Field(30, description="Timeout in seconds for the scanner")
    max_retries: int = Field(3, description="Maximum number of retries on failure")
    intensity: ScannerIntensity = Field(ScannerIntensity.MEDIUM, description="Resource intensity level")
    options: Dict[str, Any] = Field(default_factory=dict, description="Scanner-specific options")
    concurrent_requests: int = Field(5, description="Maximum number of concurrent requests")
    rate_limit: Optional[int] = Field(None, description="Requests per second limit")
    timeout_per_request: int = Field(10, description="Timeout per individual request in seconds")

    @field_validator('timeout')
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Timeout must be at least 1 second")
        if v > 3600:
            raise ValueError("Timeout cannot exceed 3600 seconds (1 hour)")
        return v

    @field_validator('max_retries')
    @classmethod
    def validate_max_retries(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Max retries cannot be negative")
        if v > 10:
            raise ValueError("Max retries cannot exceed 10")
        return v

    @field_validator('concurrent_requests')
    @classmethod
    def validate_concurrent_requests(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Concurrent requests must be at least 1")
        if v > 50:
            raise ValueError("Concurrent requests cannot exceed 50")
        return v

    @field_validator('timeout_per_request')
    @classmethod
    def validate_timeout_per_request(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Timeout per request must be at least 1 second")
        if v > 300:
            raise ValueError("Timeout per request cannot exceed 300 seconds")
        return v

    @model_validator(mode='after')
    def validate_intensity_options(self) -> 'ScannerConfig':
        """Validate scanner options based on intensity level."""
        if self.intensity == ScannerIntensity.HEAVY:
            if self.concurrent_requests > 10:
                self.concurrent_requests = 10
            if not self.rate_limit:
                self.rate_limit = 5
        elif self.intensity == ScannerIntensity.LIGHT:
            if self.concurrent_requests > 20:
                self.concurrent_requests = 20
            if not self.rate_limit:
                self.rate_limit = 10
        return self

class ScannerRegistryConfig(BaseModel):
    """Configuration for the scanner registry."""
    default_timeout: int = Field(30, description="Default timeout for all scanners")
    default_max_retries: int = Field(3, description="Default max retries for all scanners")
    scanner_configs: Dict[str, ScannerConfig] = Field(default_factory=dict, description="Per-scanner configurations")
    batch_size: int = Field(5, description="Number of scanners to run concurrently")
    max_concurrent_scans: int = Field(10, description="Maximum number of concurrent scans")
    resource_limits: Dict[str, Any] = Field(
        default_factory=lambda: {
            'max_cpu_percent': 80,
            'max_memory_mb': 1024,
            'max_network_connections': 100
        },
        description="Resource usage limits"
    )
    default_intensity: ScannerIntensity = Field(
        ScannerIntensity.MEDIUM,
        description="Default intensity level for scanners"
    )
    enable_adaptive_concurrency: bool = Field(
        True,
        description="Whether to enable adaptive concurrency based on resource usage"
    )
    adaptive_concurrency_interval: int = Field(
        5,
        description="Interval in seconds for checking and adjusting concurrency"
    )

    @field_validator('batch_size')
    @classmethod
    def validate_batch_size(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Batch size must be at least 1")
        if v > 20:
            raise ValueError("Batch size cannot exceed 20")
        return v

    @field_validator('max_concurrent_scans')
    @classmethod
    def validate_max_concurrent_scans(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Max concurrent scans must be at least 1")
        if v > 50:
            raise ValueError("Max concurrent scans cannot exceed 50")
        return v

    @field_validator('adaptive_concurrency_interval')
    @classmethod
    def validate_adaptive_concurrency_interval(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Adaptive concurrency interval must be at least 1 second")
        if v > 60:
            raise ValueError("Adaptive concurrency interval cannot exceed 60 seconds")
        return v

    @model_validator(mode='after')
    def validate_resource_limits(self) -> 'ScannerRegistryConfig':
        """Validate resource limits and set defaults if missing."""
        limits = self.resource_limits
        if 'max_cpu_percent' not in limits or limits['max_cpu_percent'] > 100:
            limits['max_cpu_percent'] = 80
        if 'max_memory_mb' not in limits or limits['max_memory_mb'] < 256:
            limits['max_memory_mb'] = 1024
        if 'max_network_connections' not in limits or limits['max_network_connections'] < 10:
            limits['max_network_connections'] = 100
        return self

    class Config:
        """Pydantic model configuration."""
        validate_assignment = True
        extra = "forbid"
        json_encoders = {
            ScannerIntensity: lambda v: v.value
        } 
