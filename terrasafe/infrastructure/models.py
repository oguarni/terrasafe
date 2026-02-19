"""
Database models for TerraSafe.
Defines tables for scans, vulnerabilities, and scan history.
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    String, Integer, Float, DateTime, Text, JSON, Boolean, ForeignKey, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid import uuid4

from terrasafe.infrastructure.database import Base


class Scan(Base):
    """
    Represents a security scan of a Terraform file.

    Stores scan metadata, results, and relationships to detected vulnerabilities.
    """
    __tablename__ = "scans"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
        comment="Unique scan identifier (UUID)"
    )

    # File information
    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Name of the scanned Terraform file"
    )
    file_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="SHA-256 hash of file content"
    )
    file_size_bytes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="File size in bytes"
    )

    # Scan results
    score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Overall security score (0-100, higher = more risky)"
    )
    rule_based_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Score from rule-based analysis"
    )
    ml_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Score from ML model"
    )
    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Confidence level: LOW, MEDIUM, HIGH"
    )

    # Scan metadata
    scan_duration_seconds: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Time taken to scan in seconds"
    )
    from_cache: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        comment="Whether result was from cache"
    )

    # Features analyzed
    features_analyzed: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Feature vector used by ML model"
    )

    # Vulnerability summary
    vulnerability_summary: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Summary of vulnerabilities by severity"
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
        comment="When the scan was performed"
    )

    # User/API information (optional)
    user_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="User or API key identifier who requested the scan"
    )
    correlation_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True,
        comment="Request correlation ID for tracing"
    )

    # Environment
    environment: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="Environment where scan was performed (dev, staging, prod)"
    )

    # Relationships
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin"
    )

    # Indexes for common queries
    __table_args__ = (
        Index('idx_scan_score', 'score'),
    )

    def __repr__(self) -> str:
        return (
            f"<Scan(id={self.id}, filename={self.filename}, "
            f"score={self.score}, created_at={self.created_at})>"
        )


class Vulnerability(Base):
    """
    Represents a security vulnerability detected in a scan.

    Each vulnerability is linked to a specific scan and contains
    details about the issue and recommended remediation.
    """
    __tablename__ = "vulnerabilities"

    # Primary key
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique vulnerability identifier"
    )

    # Foreign key to scan
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="ID of the scan that detected this vulnerability"
    )

    # Vulnerability details
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
        comment="Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"
    )
    points: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Risk points assigned to this vulnerability"
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Description of the vulnerability"
    )
    resource: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Terraform resource where vulnerability was found"
    )
    remediation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Recommended remediation steps"
    )

    # Categorization
    category: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Category: hardcoded_secret, open_port, public_access, etc."
    )

    # Rule information
    rule_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="ID of the security rule that detected this"
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When the vulnerability was detected"
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="vulnerabilities"
    )

    # Indexes (only if needed beyond column-level index=True)
    __table_args__ = tuple()

    def __repr__(self) -> str:
        return (
            f"<Vulnerability(id={self.id}, severity={self.severity}, "
            f"resource={self.resource})>"
        )


class ScanHistory(Base):
    """
    Tracks scan history and trends over time.

    Used for analytics, reporting, and identifying security trends.
    """
    __tablename__ = "scan_history"

    # Primary key
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique history entry identifier"
    )

    # Reference to scan
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="ID of the related scan"
    )

    # Aggregated metrics
    date: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        index=True,
        comment="Date of the history entry"
    )
    total_scans: Mapped[int] = mapped_column(
        Integer,
        default=0,
        comment="Total number of scans performed"
    )
    average_score: Mapped[float] = mapped_column(
        Float,
        nullable=True,
        comment="Average security score"
    )
    critical_vulnerabilities: Mapped[int] = mapped_column(
        Integer,
        default=0,
        comment="Number of critical vulnerabilities found"
    )
    high_vulnerabilities: Mapped[int] = mapped_column(
        Integer,
        default=0,
        comment="Number of high severity vulnerabilities"
    )

    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When this history entry was created"
    )

    def __repr__(self) -> str:
        return (
            f"<ScanHistory(id={self.id}, date={self.date}, "
            f"total_scans={self.total_scans})>"
        )


class MLModelVersion(Base):
    """
    Tracks ML model versions and metadata.

    Enables model versioning, A/B testing, and performance tracking.
    """
    __tablename__ = "ml_model_versions"

    # Primary key
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique model version identifier"
    )

    # Model information
    version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        unique=True,
        comment="Model version (e.g., 1.0.0, 1.1.0)"
    )
    model_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Type of model (e.g., IsolationForest)"
    )
    file_path: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Path to the model file"
    )

    # Metrics
    accuracy: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Model accuracy score"
    )
    precision: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Model precision score"
    )
    recall: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Model recall score"
    )
    f1_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Model F1 score"
    )

    # Training information
    training_samples: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Number of samples used for training"
    )
    training_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="When the model was trained"
    )

    # Deployment
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        index=True,
        comment="Whether this version is currently active"
    )
    deployed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="When this version was deployed"
    )

    # Model metadata (renamed from metadata to avoid SQLAlchemy reserved name conflict)
    model_metadata: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Additional model metadata"
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="When this version was created"
    )

    def __repr__(self) -> str:
        return (
            f"<MLModelVersion(id={self.id}, version={self.version}, "
            f"is_active={self.is_active})>"
        )
