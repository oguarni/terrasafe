"""
Integration tests for terrasafe.infrastructure.repositories module.

These tests verify the repository pattern implementation including:
- ScanRepository CRUD operations
- VulnerabilityRepository operations
- MLModelVersionRepository operations
- Query methods with filters
- Statistics and aggregations
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4

from terrasafe.infrastructure.repositories import (
    ScanRepository,
    VulnerabilityRepository,
    MLModelVersionRepository
)
from terrasafe.infrastructure.models import Scan, Vulnerability, MLModelVersion
from terrasafe.domain.models import Vulnerability as DomainVulnerability, Severity


class TestScanRepository:
    """Test suite for ScanRepository class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock AsyncSession."""
        session = AsyncMock(spec=AsyncSession)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.execute = AsyncMock()
        session.delete = AsyncMock()
        return session

    @pytest.fixture
    def scan_repo(self, mock_session):
        """Create a ScanRepository instance."""
        return ScanRepository(mock_session)

    @pytest.fixture
    def sample_scan_data(self):
        """Provide sample scan data for testing."""
        return {
            'filename': 'test.tf',
            'file_hash': 'a' * 64,
            'file_size_bytes': 1024,
            'score': 75,
            'rule_based_score': 70,
            'ml_score': 0.85,
            'confidence': 'high',
            'scan_duration_seconds': 1.5,
            'from_cache': False,
            'features_analyzed': {'resources': 5, 'variables': 3},
            'vulnerability_summary': {'CRITICAL': 2, 'HIGH': 3},
            'vulnerabilities': []
        }

    @pytest.mark.asyncio
    async def test_create_scan_basic(self, scan_repo, mock_session, sample_scan_data):
        """Test creating a basic scan without vulnerabilities."""
        scan = await scan_repo.create(**sample_scan_data)

        # Verify session methods were called
        assert mock_session.add.called
        assert mock_session.flush.call_count >= 1

        # Verify scan object was created
        added_obj = mock_session.add.call_args[0][0]
        assert isinstance(added_obj, Scan)
        assert added_obj.filename == 'test.tf'
        assert added_obj.score == 75

    @pytest.mark.asyncio
    async def test_create_scan_with_vulnerabilities(self, scan_repo, mock_session, sample_scan_data):
        """Test creating a scan with vulnerabilities."""
        vulnerabilities = [
            {
                'severity': 'CRITICAL',
                'points': 50,
                'message': 'Hardcoded secret found',
                'resource': 'aws_instance.example',
                'remediation': 'Use secrets manager'
            },
            {
                'severity': 'HIGH',
                'points': 30,
                'message': 'Open security group to internet',
                'resource': 'aws_security_group.example',
                'remediation': 'Restrict CIDR blocks'
            }
        ]
        sample_scan_data['vulnerabilities'] = vulnerabilities

        scan = await scan_repo.create(**sample_scan_data)

        # Verify vulnerabilities were added
        add_calls = mock_session.add.call_args_list
        assert len(add_calls) >= 3  # 1 scan + 2 vulnerabilities

    @pytest.mark.asyncio
    async def test_create_scan_with_optional_fields(self, scan_repo, mock_session, sample_scan_data):
        """Test creating a scan with optional fields."""
        sample_scan_data.update({
            'user_id': 'user123',
            'correlation_id': 'corr456',
            'environment': 'production'
        })

        scan = await scan_repo.create(**sample_scan_data)

        added_obj = mock_session.add.call_args_list[0][0][0]
        assert added_obj.user_id == 'user123'
        assert added_obj.correlation_id == 'corr456'
        assert added_obj.environment == 'production'

    @pytest.mark.asyncio
    async def test_get_by_id_found(self, scan_repo, mock_session):
        """Test retrieving a scan by ID when it exists."""
        scan_id = str(uuid4())
        mock_scan = Scan(id=scan_id, filename='test.tf', score=80)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_session.execute.return_value = mock_result

        result = await scan_repo.get_by_id(scan_id)

        assert result == mock_scan
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, scan_repo, mock_session):
        """Test retrieving a scan by ID when it doesn't exist."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await scan_repo.get_by_id('00000000-0000-0000-0000-000000000000')

        assert result is None

    @pytest.mark.asyncio
    async def test_get_by_file_hash(self, scan_repo, mock_session):
        """Test retrieving scans by file hash."""
        file_hash = 'b' * 64
        mock_scans = [
            Scan(id=str(uuid4()), filename='test1.tf', file_hash=file_hash),
            Scan(id=str(uuid4()), filename='test2.tf', file_hash=file_hash)
        ]

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_scans
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        result = await scan_repo.get_by_file_hash(file_hash, limit=10)

        assert len(result) == 2
        assert all(scan.file_hash == file_hash for scan in result)

    @pytest.mark.asyncio
    async def test_get_recent_scans_no_filter(self, scan_repo, mock_session):
        """Test retrieving recent scans without user filter."""
        mock_scans = [Scan(id=str(uuid4()), filename=f'test{i}.tf') for i in range(5)]

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_scans
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        result = await scan_repo.get_recent_scans(limit=5)

        assert len(result) == 5

    @pytest.mark.asyncio
    async def test_get_recent_scans_with_user_filter(self, scan_repo, mock_session):
        """Test retrieving recent scans filtered by user."""
        user_id = 'user123'
        mock_scans = [Scan(id=str(uuid4()), filename='test.tf', user_id=user_id)]

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_scans
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        result = await scan_repo.get_recent_scans(limit=10, user_id=user_id)

        assert len(result) == 1
        assert result[0].user_id == user_id

    @pytest.mark.asyncio
    async def test_get_high_risk_scans(self, scan_repo, mock_session):
        """Test retrieving high-risk scans."""
        mock_scans = [
            Scan(id=str(uuid4()), filename='high1.tf', score=85),
            Scan(id=str(uuid4()), filename='high2.tf', score=90)
        ]

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_scans
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        result = await scan_repo.get_high_risk_scans(threshold=70, limit=50)

        assert len(result) == 2
        assert all(scan.score >= 70 for scan in mock_scans)

    @pytest.mark.asyncio
    async def test_get_stats_no_filter(self, scan_repo, mock_session):
        """Test getting statistics without date filters."""
        mock_row = MagicMock()
        mock_row.total_scans = 100
        mock_row.avg_score = 65.5
        mock_row.max_score = 95
        mock_row.min_score = 10
        mock_row.avg_duration = 2.345

        mock_result = MagicMock()
        mock_result.one.return_value = mock_row
        mock_session.execute.return_value = mock_result

        stats = await scan_repo.get_stats()

        assert stats['total_scans'] == 100
        assert stats['average_score'] == 65.5
        assert stats['max_score'] == 95
        assert stats['min_score'] == 10
        assert stats['average_duration'] == 2.345

    @pytest.mark.asyncio
    async def test_get_stats_with_date_filter(self, scan_repo, mock_session):
        """Test getting statistics with date filters."""
        start_date = datetime.utcnow() - timedelta(days=7)
        end_date = datetime.utcnow()

        mock_row = MagicMock()
        mock_row.total_scans = 50
        mock_row.avg_score = 70.0
        mock_row.max_score = 90
        mock_row.min_score = 30
        mock_row.avg_duration = 1.5

        mock_result = MagicMock()
        mock_result.one.return_value = mock_row
        mock_session.execute.return_value = mock_result

        stats = await scan_repo.get_stats(start_date=start_date, end_date=end_date)

        assert stats['total_scans'] == 50

    @pytest.mark.asyncio
    async def test_delete_old_scans(self, scan_repo, mock_session):
        """Test deleting old scans."""
        old_scans = [Scan(id=str(uuid4()), filename=f'old{i}.tf') for i in range(3)]

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = old_scans
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        count = await scan_repo.delete_old_scans(days=90)

        assert count == 3
        assert mock_session.delete.call_count == 3

    @pytest.mark.asyncio
    async def test_categorize_vulnerability_hardcoded_secret(self, scan_repo):
        """Test vulnerability categorization for hardcoded secrets."""
        category = scan_repo._categorize_vulnerability("Hardcoded secret found in code")
        assert category == 'hardcoded_secret'

    @pytest.mark.asyncio
    async def test_categorize_vulnerability_open_port(self, scan_repo):
        """Test vulnerability categorization for open ports."""
        category = scan_repo._categorize_vulnerability("Open security group exposed to internet")
        assert category == 'open_port'

    @pytest.mark.asyncio
    async def test_categorize_vulnerability_public_access(self, scan_repo):
        """Test vulnerability categorization for public access."""
        category = scan_repo._categorize_vulnerability("S3 bucket is public")
        assert category == 'public_access'

    @pytest.mark.asyncio
    async def test_categorize_vulnerability_other(self, scan_repo):
        """Test vulnerability categorization for other types."""
        category = scan_repo._categorize_vulnerability("Some other vulnerability")
        assert category == 'other'


class TestVulnerabilityRepository:
    """Test suite for VulnerabilityRepository class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock AsyncSession."""
        session = AsyncMock(spec=AsyncSession)
        session.execute = AsyncMock()
        return session

    @pytest.fixture
    def vuln_repo(self, mock_session):
        """Create a VulnerabilityRepository instance."""
        return VulnerabilityRepository(mock_session)

    @pytest.mark.asyncio
    async def test_get_by_scan_id(self, vuln_repo, mock_session):
        """Test retrieving vulnerabilities by scan ID."""
        scan_id = str(uuid4())
        mock_vulns = [
            Vulnerability(id=str(uuid4()), scan_id=scan_id, severity='CRITICAL'),
            Vulnerability(id=str(uuid4()), scan_id=scan_id, severity='HIGH')
        ]

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_vulns
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        result = await vuln_repo.get_by_scan_id(scan_id)

        assert len(result) == 2
        assert all(v.scan_id == scan_id for v in result)

    @pytest.mark.asyncio
    async def test_get_by_severity(self, vuln_repo, mock_session):
        """Test retrieving vulnerabilities by severity."""
        severity = 'CRITICAL'
        mock_vulns = [
            Vulnerability(id=str(uuid4()), severity=severity),
            Vulnerability(id=str(uuid4()), severity=severity)
        ]

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_vulns
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        result = await vuln_repo.get_by_severity(severity, limit=100)

        assert len(result) == 2
        assert all(v.severity == severity for v in result)

    @pytest.mark.asyncio
    async def test_get_stats_by_category(self, vuln_repo, mock_session):
        """Test getting vulnerability statistics by category."""
        mock_rows = [
            MagicMock(category='hardcoded_secret', count=10),
            MagicMock(category='open_port', count=5),
            MagicMock(category='public_access', count=3)
        ]

        mock_result = MagicMock()
        mock_result.all.return_value = mock_rows
        mock_session.execute.return_value = mock_result

        stats = await vuln_repo.get_stats_by_category()

        assert stats['hardcoded_secret'] == 10
        assert stats['open_port'] == 5
        assert stats['public_access'] == 3


class TestMLModelVersionRepository:
    """Test suite for MLModelVersionRepository class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock AsyncSession."""
        session = AsyncMock(spec=AsyncSession)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.execute = AsyncMock()
        return session

    @pytest.fixture
    def model_repo(self, mock_session):
        """Create an MLModelVersionRepository instance."""
        return MLModelVersionRepository(mock_session)

    @pytest.fixture
    def sample_model_data(self):
        """Provide sample model data for testing."""
        return {
            'version': 'v1.0.0',
            'model_type': 'random_forest',
            'file_path': '/models/rf_v1.pkl',
            'accuracy': 0.95,
            'precision': 0.93,
            'recall': 0.92,
            'f1_score': 0.925,
            'training_samples': 10000,
            'training_date': datetime.utcnow(),
            'metadata': {'features': 50, 'depth': 10}
        }

    @pytest.mark.asyncio
    async def test_create_model_version(self, model_repo, mock_session, sample_model_data):
        """Test creating a new model version."""
        model = await model_repo.create(**sample_model_data)

        # Verify session methods were called
        assert mock_session.add.called
        assert mock_session.flush.called

        # Verify model object
        added_obj = mock_session.add.call_args[0][0]
        assert isinstance(added_obj, MLModelVersion)
        assert added_obj.version == 'v1.0.0'
        assert added_obj.accuracy == 0.95

    @pytest.mark.asyncio
    async def test_create_model_version_minimal(self, model_repo, mock_session):
        """Test creating a model version with minimal fields."""
        minimal_data = {
            'version': 'v2.0.0',
            'model_type': 'xgboost',
            'file_path': '/models/xgb_v2.pkl'
        }

        model = await model_repo.create(**minimal_data)

        added_obj = mock_session.add.call_args[0][0]
        assert added_obj.version == 'v2.0.0'
        assert added_obj.model_type == 'xgboost'

    @pytest.mark.asyncio
    async def test_get_active_version_found(self, model_repo, mock_session):
        """Test retrieving the active model version when it exists."""
        mock_model = MLModelVersion(
            version='v1.0.0',
            model_type='random_forest',
            file_path='/models/rf.pkl',
            is_active=True
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_model
        mock_session.execute.return_value = mock_result

        result = await model_repo.get_active_version()

        assert result == mock_model
        assert result.is_active is True

    @pytest.mark.asyncio
    async def test_get_active_version_not_found(self, model_repo, mock_session):
        """Test retrieving active model version when none exists."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await model_repo.get_active_version()

        assert result is None

    @pytest.mark.asyncio
    async def test_set_active_version(self, model_repo, mock_session):
        """Test setting a model version as active."""
        version = 'v2.0.0'

        # Mock getting currently active versions
        old_model = MLModelVersion(version='v1.0.0', is_active=True)
        mock_result1 = MagicMock()
        mock_scalars1 = MagicMock()
        mock_scalars1.all.return_value = [old_model]
        mock_result1.scalars.return_value = mock_scalars1

        # Mock getting the version to activate
        new_model = MLModelVersion(version=version, is_active=False)
        mock_result2 = MagicMock()
        mock_result2.scalar_one.return_value = new_model

        mock_session.execute.side_effect = [mock_result1, mock_result2]

        result = await model_repo.set_active_version(version)

        # Verify old model was deactivated
        assert old_model.is_active is False

        # Verify new model was activated
        assert new_model.is_active is True
        assert new_model.deployed_at is not None

        # Verify flush was called
        assert mock_session.flush.called

    @pytest.mark.asyncio
    async def test_get_all_versions(self, model_repo, mock_session):
        """Test retrieving all model versions."""
        mock_models = [
            MLModelVersion(version='v1.0.0', is_active=False),
            MLModelVersion(version='v2.0.0', is_active=True),
            MLModelVersion(version='v3.0.0', is_active=False)
        ]

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_models
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        result = await model_repo.get_all_versions()

        assert len(result) == 3
        assert result[0].version == 'v1.0.0'
        assert result[1].is_active is True
