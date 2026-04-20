"""Domain models - Core business entities"""
from enum import Enum
from dataclasses import dataclass, field
from typing import List

from .compliance_frameworks import FrameworkReference


class Severity(Enum):
    """Security severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    """Represents a security vulnerability"""
    severity: Severity
    points: int
    message: str
    resource: str
    remediation: str = ""
    rule_id: str = ""
    frameworks: List[FrameworkReference] = field(default_factory=list)
