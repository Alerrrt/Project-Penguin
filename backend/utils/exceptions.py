class ScanTimeoutError(Exception):
    """Raised when a scan exceeds the maximum allowed time."""
    pass
 
class InvalidTargetError(Exception):
    """Raised when the scan target is invalid or malformed."""
    pass 
