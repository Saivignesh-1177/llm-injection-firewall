"""pifw: a dependency-free prompt-injection firewall for LLM applications."""
from .canary import CanaryVault
from .sanitize import normalize, spotlight
from .scanner import Finding, ScanResult, scan

__all__ = ["Finding", "ScanResult", "scan", "CanaryVault", "normalize", "spotlight"]
__version__ = "0.1.0"
