from pydantic import BaseModel, HttpUrl, Field
from typing import Dict, List, Optional, Union, Any
from enum import Enum
from datetime import datetime

class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    RECON = "Recon"

class OwaspCategory(str, Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"  # Alias for easier reference
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"  # Alias
    A03_INJECTION = "A03:2021 - Injection"
    INJECTION = "A03:2021 - Injection"  # Alias
    A03_XSS = "A03:2021 - Cross-Site Scripting (XSS)"
    XSS = "A03:2021 - Cross-Site Scripting (XSS)"  # Alias
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    INSECURE_DESIGN = "A04:2021 - Insecure Design"  # Alias
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"  # Alias
    A06_VULNERABLE_AND_OUTDATED_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    VULNERABLE_AND_OUTDATED_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"  # Alias
    A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES = "A07:2021 - Identification and Authentication Failures"
    IDENTIFICATION_AND_AUTHENTICATION_FAILURES = "A07:2021 - Identification and Authentication Failures"  # Alias
    A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    SOFTWARE_AND_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"  # Alias
    A09_SECURITY_LOGGING_AND_MONITORING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    LOGGING_AND_MONITORING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"  # Alias
    A10_SERVER_SIDE_REQUEST_FORGERY_SSRF = "A10:2021 - Server-Side Request Forgery (SSRF)"
    SSRF = "A10:2021 - Server-Side Request Forgery (SSRF)"  # Alias
    SERVER_SIDE_REQUEST_FORGERY_SSRF = "A10:2021 - Server-Side Request Forgery (SSRF)"  # Alias
    UNKNOWN = "Unknown" # Added for default if no specific category is matched

class HistoricalScanSummary(BaseModel):
    scan_id: str
    target: str
    start_time: str # Use a string for simplicity, datetime in real app
    status: str # e.g., "completed", "running", "failed"
    finding_count: int
    severity_counts: dict[str, int] # e.g., {"Critical": 2, "High": 5}
    overall_score: float

class ScanInput(BaseModel):
    """Model for representing scan input."""
    target: str
    scan_type: str
    options: Optional[Dict] = Field(default_factory=dict)

# New Pydantic model for the scan start request body
class ScanStartRequest(BaseModel):
    target: str = Field(..., description="The target URL to scan.")
    scan_type: str = Field("full_scan", description="The type of scan to perform. Defaults to 'full_scan'.")
    options: Optional[Dict[str, Any]] = Field(None, description="Optional scan parameters.")

class PluginConfig(BaseModel):
    """Minimal plugin config model for plugin manager compatibility."""
    options: Optional[Dict[str, object]] = None

class ModuleStatus(BaseModel):
    """Status of an individual scanning module. Includes error for reporting failures."""
    module_name: str
    status: str # e.g., "started", "running", "completed", "failed"
    progress: int = Field(0, ge=0, le=100) # Percentage complete
    error: Optional[str] = None

class RequestLog(BaseModel):
    """Details of an HTTP request."""
    method: str
    url: str
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None # Could be bytes, but str for simplicity

class FindingDetails(BaseModel):
    """Additional details about a finding."""
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    response_status: Optional[int] = None
    response_body_snippet: Optional[str] = None
    context: Optional[str] = Field(None, description="General context string related to the finding.")

class Finding(BaseModel):
    """Model for representing a security finding."""
    id: str
    type: str
    severity: str
    title: str
    description: str
    location: str
    evidence: Optional[Any] = None
    timestamp: datetime = Field(default_factory=datetime.now)

class ScanResult(BaseModel):
    scan_id: str
    target: str
    status: str
    findings: List[Finding] = Field(default_factory=list)
    start_time: datetime
    end_time: Optional[datetime] = None
    errors: List[str] = Field(default_factory=list)
