"""Domain models - Core business entities"""
from enum import Enum
from dataclasses import dataclass

class Severity(Enum):
    """Security severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Vulnerability:
    """Represents a security vulnerability"""
    severity: Severity
    points: int
    message: str
    resource: str
    remediation: str = ""
