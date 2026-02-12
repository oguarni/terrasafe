"""
Repository pattern for database access in TerraSafe.
Provides clean abstraction over database operations.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from terrasafe.infrastructure.models import Scan, Vulnerability, ScanHistory, MLModelVersion
from terrasafe.domain.models import Vulnerability as DomainVulnerability, Severity
from terrasafe.infrastructure.validation import validate_file_hash, validate_scan_id, sanitize_filename

logger = logging.getLogger(__name__)


class ScanRepository:
    """Repository for Scan database operations."""

    def __init__(self, session: AsyncSession):
        """
        Initialize repository with database session.

        Args:
            session: AsyncSession for database operations
        """
        self.session = session

    async def create(
        self,
        filename: str,
        file_hash: str,
        file_size_bytes: int,
        score: int,
        rule_based_score: int,
        ml_score: float,
        confidence: str,
        scan_duration_seconds: float,
        from_cache: bool,
        features_analyzed: Dict[str, Any],
        vulnerability_summary: Dict[str, int],
        vulnerabilities: List[DomainVulnerability],
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> Scan:
        """
        Create a new scan record.

        Args:
            filename: Name of the scanned file
            file_hash: SHA-256 hash of file content
            file_size_bytes: File size in bytes
            score: Overall security score
            rule_based_score: Rule-based analysis score
            ml_score: ML model score
            confidence: Confidence level
            scan_duration_seconds: Scan duration
            from_cache: Whether result was cached
            features_analyzed: Feature vector
            vulnerability_summary: Summary by severity
            vulnerabilities: List of detected vulnerabilities
            user_id: User identifier
            correlation_id: Request correlation ID
            environment: Environment name

        Returns:
            Created Scan object
        """
        # Validate and sanitize inputs
        filename = sanitize_filename(filename)
        file_hash = validate_file_hash(file_hash)

        scan = Scan(
            filename=filename,
            file_hash=file_hash,
            file_size_bytes=file_size_bytes,
            score=score,
            rule_based_score=rule_based_score,
            ml_score=ml_score,
            confidence=confidence,
            scan_duration_seconds=scan_duration_seconds,
            from_cache=from_cache,
            features_analyzed=features_analyzed,
            vulnerability_summary=vulnerability_summary,
            user_id=user_id,
            correlation_id=correlation_id,
            environment=environment,
        )

        self.session.add(scan)

        # Flush to get the scan ID before adding vulnerabilities
        await self.session.flush()

        # Add vulnerabilities
        for vuln in vulnerabilities:
            # Handle both Vulnerability objects and dictionaries
            if isinstance(vuln, dict):
                severity = vuln['severity']
                points = vuln['points']
                message = vuln['message']
                resource = vuln['resource']
                remediation = vuln['remediation']
            else:
                severity = vuln.severity.value
                points = vuln.points
                message = vuln.message
                resource = vuln.resource
                remediation = vuln.remediation

            db_vuln = Vulnerability(
                scan_id=scan.id,
                severity=severity,
                points=points,
                message=message,
                resource=resource,
                remediation=remediation,
                category=self._categorize_vulnerability(message),
            )
            self.session.add(db_vuln)

        await self.session.flush()
        logger.info(f"Created scan record: {scan.id}")
        return scan

    async def get_by_id(self, scan_id: str) -> Optional[Scan]:
        """
        Get scan by ID.

        Args:
            scan_id: Scan identifier

        Returns:
            Scan object or None if not found
        """
        # Validate scan ID format
        scan_id = validate_scan_id(scan_id)

        result = await self.session.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def get_by_file_hash(
        self,
        file_hash: str,
        limit: int = 10
    ) -> List[Scan]:
        """
        Get scans by file hash.

        Args:
            file_hash: SHA-256 hash of file
            limit: Maximum number of results

        Returns:
            List of Scan objects
        """
        # Validate file hash format
        file_hash = validate_file_hash(file_hash)

        result = await self.session.execute(
            select(Scan)
            .where(Scan.file_hash == file_hash)
            .order_by(desc(Scan.created_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_recent_scans(
        self,
        limit: int = 100,
        user_id: Optional[str] = None
    ) -> List[Scan]:
        """
        Get recent scans.

        Args:
            limit: Maximum number of results
            user_id: Filter by user ID (optional)

        Returns:
            List of Scan objects
        """
        query = select(Scan).order_by(desc(Scan.created_at)).limit(limit)

        if user_id:
            query = query.where(Scan.user_id == user_id)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_high_risk_scans(
        self,
        threshold: int = 70,
        limit: int = 50
    ) -> List[Scan]:
        """
        Get high-risk scans (score >= threshold).

        Args:
            threshold: Minimum score for high risk
            limit: Maximum number of results

        Returns:
            List of Scan objects
        """
        result = await self.session.execute(
            select(Scan)
            .where(Scan.score >= threshold)
            .order_by(desc(Scan.score))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_stats(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get scan statistics.

        Args:
            start_date: Start date for filtering
            end_date: End date for filtering

        Returns:
            Dictionary with statistics
        """
        query = select(
            func.count(Scan.id).label('total_scans'),
            func.avg(Scan.score).label('avg_score'),
            func.max(Scan.score).label('max_score'),
            func.min(Scan.score).label('min_score'),
            func.avg(Scan.scan_duration_seconds).label('avg_duration'),
        )

        if start_date:
            query = query.where(Scan.created_at >= start_date)
        if end_date:
            query = query.where(Scan.created_at <= end_date)

        result = await self.session.execute(query)
        row = result.one()

        return {
            'total_scans': row.total_scans or 0,
            'average_score': round(row.avg_score, 2) if row.avg_score else 0,
            'max_score': row.max_score or 0,
            'min_score': row.min_score or 0,
            'average_duration': round(row.avg_duration, 3) if row.avg_duration else 0,
        }

    async def delete_old_scans(self, days: int = 90) -> int:
        """
        Delete scans older than specified days.

        Args:
            days: Number of days to keep

        Returns:
            Number of deleted scans
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        result = await self.session.execute(
            select(Scan).where(Scan.created_at < cutoff_date)
        )
        scans_to_delete = result.scalars().all()

        count = len(scans_to_delete)
        for scan in scans_to_delete:
            await self.session.delete(scan)

        logger.info(f"Deleted {count} old scans (older than {days} days)")
        return count

    def _categorize_vulnerability(self, message: str) -> str:
        """
        Categorize vulnerability based on message.

        Args:
            message: Vulnerability message

        Returns:
            Category string
        """
        message_lower = message.lower()

        if 'hardcoded' in message_lower or 'secret' in message_lower:
            return 'hardcoded_secret'
        elif 'open security group' in message_lower or 'exposed to internet' in message_lower:
            return 'open_port'
        elif 's3 bucket' in message_lower and 'public' in message_lower:
            return 'public_access'
        elif 'unencrypted' in message_lower:
            return 'unencrypted_storage'
        elif 'mfa' in message_lower or 'authentication' in message_lower:
            return 'weak_authentication'
        else:
            return 'other'


class VulnerabilityRepository:
    """Repository for Vulnerability database operations."""

    def __init__(self, session: AsyncSession):
        """
        Initialize repository with database session.

        Args:
            session: AsyncSession for database operations
        """
        self.session = session

    async def get_by_scan_id(self, scan_id: str) -> List[Vulnerability]:
        """
        Get vulnerabilities for a specific scan.

        Args:
            scan_id: Scan identifier

        Returns:
            List of Vulnerability objects
        """
        # Validate scan ID format
        scan_id = validate_scan_id(scan_id)

        result = await self.session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        return list(result.scalars().all())

    async def get_by_severity(
        self,
        severity: str,
        limit: int = 100
    ) -> List[Vulnerability]:
        """
        Get vulnerabilities by severity.

        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            limit: Maximum number of results

        Returns:
            List of Vulnerability objects
        """
        result = await self.session.execute(
            select(Vulnerability)
            .where(Vulnerability.severity == severity)
            .order_by(desc(Vulnerability.created_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_stats_by_category(self) -> Dict[str, int]:
        """
        Get vulnerability statistics by category.

        Returns:
            Dictionary with counts by category
        """
        result = await self.session.execute(
            select(
                Vulnerability.category,
                func.count(Vulnerability.id).label('count')
            )
            .group_by(Vulnerability.category)
        )

        return {row.category: row.count for row in result.all()}


class MLModelVersionRepository:
    """Repository for ML model version operations."""

    def __init__(self, session: AsyncSession):
        """
        Initialize repository with database session.

        Args:
            session: AsyncSession for database operations
        """
        self.session = session

    async def create(
        self,
        version: str,
        model_type: str,
        file_path: str,
        accuracy: Optional[float] = None,
        precision: Optional[float] = None,
        recall: Optional[float] = None,
        f1_score: Optional[float] = None,
        training_samples: Optional[int] = None,
        training_date: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MLModelVersion:
        """
        Create a new model version record.

        Args:
            version: Model version string
            model_type: Type of model
            file_path: Path to model file
            accuracy: Model accuracy
            precision: Model precision
            recall: Model recall
            f1_score: Model F1 score
            training_samples: Number of training samples
            training_date: Training date
            metadata: Additional metadata

        Returns:
            Created MLModelVersion object
        """
        model = MLModelVersion(
            version=version,
            model_type=model_type,
            file_path=file_path,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            training_samples=training_samples,
            training_date=training_date,
            model_metadata=metadata,
        )

        self.session.add(model)
        await self.session.flush()

        logger.info(f"Created ML model version: {version}")
        return model

    async def get_active_version(self) -> Optional[MLModelVersion]:
        """
        Get the currently active model version.

        Returns:
            MLModelVersion object or None
        """
        result = await self.session.execute(
            select(MLModelVersion)
            .where(MLModelVersion.is_active == True)
            .order_by(desc(MLModelVersion.deployed_at))
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def set_active_version(self, version: str) -> MLModelVersion:
        """
        Set a model version as active (deactivates others).

        Args:
            version: Version to activate

        Returns:
            Activated MLModelVersion object
        """
        # Deactivate all versions
        result = await self.session.execute(
            select(MLModelVersion).where(MLModelVersion.is_active == True)
        )
        for model in result.scalars().all():
            model.is_active = False

        # Activate specified version
        result = await self.session.execute(
            select(MLModelVersion).where(MLModelVersion.version == version)
        )
        model = result.scalar_one()
        model.is_active = True
        model.deployed_at = datetime.utcnow()

        await self.session.flush()

        logger.info(f"Activated ML model version: {version}")
        return model

    async def get_all_versions(self) -> List[MLModelVersion]:
        """
        Get all model versions.

        Returns:
            List of MLModelVersion objects
        """
        result = await self.session.execute(
            select(MLModelVersion).order_by(desc(MLModelVersion.created_at))
        )
        return list(result.scalars().all())
