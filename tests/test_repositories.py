"""Unit tests for the repository layer.

The repositories are thin adapters over AsyncSession, so these tests use a
named FakeAsyncSession rather than a live database: they assert the objects the
repositories build, the input validation they apply, and the shape of the values
they return. Query construction itself is exercised only indirectly — SQLAlchemy
is trusted to translate the statements it is handed.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

import pytest

from terravault.domain.models import Severity, Vulnerability as DomainVulnerability
from terravault.infrastructure.models import MLModelVersion, Scan, Vulnerability
from terravault.infrastructure.repositories import (
    MLModelVersionRepository,
    ScanRepository,
    VulnerabilityRepository,
)


pytestmark = pytest.mark.unit

VALID_HASH = "a" * 64
VALID_SCAN_ID = "550e8400-e29b-41d4-a716-446655440000"


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class FakeResult:
    """Stands in for the Result object AsyncSession.execute() returns."""

    def __init__(self, items: Optional[List[Any]] = None, row: Any = None):
        self._items = items or []
        self._row = row

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None

    def scalar_one(self):
        if not self._items:
            raise AssertionError("scalar_one() called with no rows staged")
        return self._items[0]

    def scalars(self):
        return self

    def all(self):
        return list(self._items)

    def one(self):
        return self._row


class FakeAsyncSession:
    """Records what the repository does instead of touching a database.

    Each execute() call pops the next staged result, so a test stages results in
    the order its repository method issues queries.
    """

    def __init__(self, results: Optional[List[FakeResult]] = None):
        self._results = list(results or [])
        self.added: List[Any] = []
        self.deleted: List[Any] = []
        self.flush_count = 0
        self.executed_statements: List[Any] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flush_count += 1

    async def delete(self, obj: Any) -> None:
        self.deleted.append(obj)

    async def execute(self, statement: Any) -> FakeResult:
        self.executed_statements.append(statement)
        return self._results.pop(0) if self._results else FakeResult()


def make_domain_vulnerability(message: str = "S3 bucket is public") -> DomainVulnerability:
    return DomainVulnerability(
        severity=Severity.HIGH,
        points=20,
        message=message,
        resource="aws_s3_bucket.data",
        remediation="Set acl to private",
    )


CREATE_ARGS = dict(
    filename="main.tf",
    file_hash=VALID_HASH,
    file_size_bytes=2048,
    score=75,
    rule_based_score=60,
    ml_score=0.42,
    confidence="high",
    scan_duration_seconds=1.25,
    from_cache=False,
    features_analyzed={"resource_count": 4},
    vulnerability_summary={"HIGH": 1},
)


# ---------------------------------------------------------------------------
# ScanRepository.create
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_persists_the_scan_and_its_vulnerabilities():
    session = FakeAsyncSession()
    repo = ScanRepository(session)

    scan = await repo.create(**CREATE_ARGS, vulnerabilities=[make_domain_vulnerability()])

    assert isinstance(scan, Scan)
    assert scan.filename == "main.tf"
    assert scan.score == 75
    # One Scan plus one Vulnerability.
    assert len(session.added) == 2
    assert isinstance(session.added[1], Vulnerability)


@pytest.mark.asyncio
async def test_create_flushes_before_and_after_adding_vulnerabilities():
    """The first flush must assign scan.id before vulnerabilities reference it."""
    session = FakeAsyncSession()
    repo = ScanRepository(session)

    await repo.create(**CREATE_ARGS, vulnerabilities=[make_domain_vulnerability()])

    assert session.flush_count == 2


@pytest.mark.asyncio
async def test_create_accepts_vulnerabilities_as_dicts():
    """The type hint says dataclass, but callers also pass plain dicts."""
    session = FakeAsyncSession()
    repo = ScanRepository(session)

    await repo.create(
        **CREATE_ARGS,
        vulnerabilities=[
            {
                "severity": "CRITICAL",
                "points": 40,
                "message": "Security group open to 0.0.0.0/0",
                "resource": "aws_security_group.web",
                "remediation": "Restrict ingress",
            }
        ],
    )

    stored = session.added[1]
    assert stored.severity == "CRITICAL"
    assert stored.points == 40


@pytest.mark.asyncio
async def test_create_derives_a_category_from_the_message():
    session = FakeAsyncSession()
    repo = ScanRepository(session)

    await repo.create(
        **CREATE_ARGS,
        vulnerabilities=[make_domain_vulnerability("S3 bucket is publicly readable")],
    )

    assert session.added[1].category is not None


@pytest.mark.asyncio
async def test_create_sanitizes_the_filename():
    session = FakeAsyncSession()
    repo = ScanRepository(session)

    scan = await repo.create(
        **{**CREATE_ARGS, "filename": "../../etc/passwd"},
        vulnerabilities=[],
    )

    assert "/" not in scan.filename


@pytest.mark.asyncio
async def test_create_rejects_a_malformed_file_hash():
    session = FakeAsyncSession()
    repo = ScanRepository(session)

    with pytest.raises(ValueError):
        await repo.create(**{**CREATE_ARGS, "file_hash": "not-a-hash"}, vulnerabilities=[])


@pytest.mark.asyncio
async def test_create_with_no_vulnerabilities_adds_only_the_scan():
    session = FakeAsyncSession()
    repo = ScanRepository(session)

    await repo.create(**CREATE_ARGS, vulnerabilities=[])

    assert len(session.added) == 1


# ---------------------------------------------------------------------------
# ScanRepository reads
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_by_id_returns_the_matching_scan():
    expected = Scan(filename="main.tf")
    repo = ScanRepository(FakeAsyncSession([FakeResult([expected])]))

    assert await repo.get_by_id(VALID_SCAN_ID) is expected


@pytest.mark.asyncio
async def test_get_by_id_returns_none_when_absent():
    repo = ScanRepository(FakeAsyncSession([FakeResult([])]))

    assert await repo.get_by_id(VALID_SCAN_ID) is None


@pytest.mark.asyncio
async def test_get_by_id_rejects_a_malformed_scan_id():
    repo = ScanRepository(FakeAsyncSession())

    with pytest.raises(ValueError):
        await repo.get_by_id("'; DROP TABLE scans; --")


@pytest.mark.asyncio
async def test_get_by_file_hash_returns_every_match():
    scans = [Scan(filename="a.tf"), Scan(filename="b.tf")]
    repo = ScanRepository(FakeAsyncSession([FakeResult(scans)]))

    assert await repo.get_by_file_hash(VALID_HASH) == scans


@pytest.mark.asyncio
async def test_get_by_file_hash_rejects_a_malformed_hash():
    repo = ScanRepository(FakeAsyncSession())

    with pytest.raises(ValueError):
        await repo.get_by_file_hash("short")


@pytest.mark.asyncio
async def test_get_recent_scans_returns_the_result_list():
    scans = [Scan(filename="a.tf")]
    repo = ScanRepository(FakeAsyncSession([FakeResult(scans)]))

    assert await repo.get_recent_scans() == scans


@pytest.mark.asyncio
async def test_get_recent_scans_accepts_a_user_filter():
    """The user_id branch adds a where clause; it must still return rows."""
    scans = [Scan(filename="a.tf")]
    repo = ScanRepository(FakeAsyncSession([FakeResult(scans)]))

    assert await repo.get_recent_scans(user_id="user-1") == scans


@pytest.mark.asyncio
async def test_get_high_risk_scans_returns_the_result_list():
    scans = [Scan(filename="risky.tf")]
    repo = ScanRepository(FakeAsyncSession([FakeResult(scans)]))

    assert await repo.get_high_risk_scans(threshold=80) == scans


# ---------------------------------------------------------------------------
# ScanRepository.get_stats
# ---------------------------------------------------------------------------

class StatsRow:
    def __init__(self, total_scans, avg_score, max_score, min_score, avg_duration):
        self.total_scans = total_scans
        self.avg_score = avg_score
        self.max_score = max_score
        self.min_score = min_score
        self.avg_duration = avg_duration


@pytest.mark.asyncio
async def test_get_stats_rounds_the_averages():
    row = StatsRow(10, 62.456, 91, 12, 1.23456)
    repo = ScanRepository(FakeAsyncSession([FakeResult(row=row)]))

    stats = await repo.get_stats()

    assert stats == {
        "total_scans": 10,
        "average_score": 62.46,
        "max_score": 91,
        "min_score": 12,
        "average_duration": 1.235,
    }


@pytest.mark.asyncio
async def test_get_stats_defaults_to_zero_on_an_empty_table():
    """avg/max/min come back as NULL when no rows match."""
    row = StatsRow(None, None, None, None, None)
    repo = ScanRepository(FakeAsyncSession([FakeResult(row=row)]))

    stats = await repo.get_stats()

    assert stats == {
        "total_scans": 0,
        "average_score": 0,
        "max_score": 0,
        "min_score": 0,
        "average_duration": 0,
    }


@pytest.mark.asyncio
async def test_get_stats_accepts_a_date_range():
    row = StatsRow(3, 50.0, 70, 30, 0.5)
    repo = ScanRepository(FakeAsyncSession([FakeResult(row=row)]))

    stats = await repo.get_stats(
        start_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end_date=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )

    assert stats["total_scans"] == 3


# ---------------------------------------------------------------------------
# ScanRepository.delete_old_scans
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delete_old_scans_deletes_each_match_and_returns_the_count():
    stale = [Scan(filename="old1.tf"), Scan(filename="old2.tf")]
    session = FakeAsyncSession([FakeResult(stale)])
    repo = ScanRepository(session)

    assert await repo.delete_old_scans(days=30) == 2
    assert session.deleted == stale


@pytest.mark.asyncio
async def test_delete_old_scans_returns_zero_when_nothing_is_stale():
    session = FakeAsyncSession([FakeResult([])])
    repo = ScanRepository(session)

    assert await repo.delete_old_scans() == 0
    assert session.deleted == []


# ---------------------------------------------------------------------------
# VulnerabilityRepository
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_by_scan_id_returns_the_vulnerabilities():
    vulns = [Vulnerability(message="public bucket")]
    repo = VulnerabilityRepository(FakeAsyncSession([FakeResult(vulns)]))

    assert await repo.get_by_scan_id(VALID_SCAN_ID) == vulns


@pytest.mark.asyncio
async def test_get_by_severity_returns_the_vulnerabilities():
    vulns = [Vulnerability(message="open security group")]
    repo = VulnerabilityRepository(FakeAsyncSession([FakeResult(vulns)]))

    assert await repo.get_by_severity("CRITICAL") == vulns


@pytest.mark.asyncio
async def test_get_stats_by_category_counts_each_category():
    class CategoryRow:
        def __init__(self, category, count):
            self.category = category
            self.count = count

    rows = [CategoryRow("storage", 4), CategoryRow("network", 2)]
    repo = VulnerabilityRepository(FakeAsyncSession([FakeResult(rows)]))

    assert await repo.get_stats_by_category() == {"storage": 4, "network": 2}


# ---------------------------------------------------------------------------
# MLModelVersionRepository
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_model_version_create_persists_and_flushes():
    session = FakeAsyncSession()
    repo = MLModelVersionRepository(session)

    model = await repo.create(
        version="1.2.0",
        model_type="IsolationForest",
        file_path="models/isolation_forest.pkl",
        accuracy=0.93,
        training_samples=5000,
    )

    assert isinstance(model, MLModelVersion)
    assert model.version == "1.2.0"
    assert session.added == [model]
    assert session.flush_count == 1


@pytest.mark.asyncio
async def test_model_version_create_maps_metadata_to_model_metadata():
    """The column is model_metadata; `metadata` is reserved by SQLAlchemy."""
    session = FakeAsyncSession()
    repo = MLModelVersionRepository(session)

    model = await repo.create(
        version="1.3.0",
        model_type="IsolationForest",
        file_path="models/v13.pkl",
        metadata={"contamination": 0.05},
    )

    assert model.model_metadata == {"contamination": 0.05}


@pytest.mark.asyncio
async def test_get_active_version_returns_the_active_model():
    active = MLModelVersion(version="1.0.0")
    repo = MLModelVersionRepository(FakeAsyncSession([FakeResult([active])]))

    assert await repo.get_active_version() is active


@pytest.mark.asyncio
async def test_get_active_version_returns_none_when_no_model_is_active():
    repo = MLModelVersionRepository(FakeAsyncSession([FakeResult([])]))

    assert await repo.get_active_version() is None


@pytest.mark.asyncio
async def test_set_active_version_deactivates_the_previous_one():
    previously_active = MLModelVersion(version="1.0.0")
    previously_active.is_active = True
    target = MLModelVersion(version="2.0.0")
    target.is_active = False

    session = FakeAsyncSession([FakeResult([previously_active]), FakeResult([target])])
    repo = MLModelVersionRepository(session)

    result = await repo.set_active_version("2.0.0")

    assert previously_active.is_active is False
    assert result is target
    assert target.is_active is True


@pytest.mark.asyncio
async def test_set_active_version_stamps_the_deployment_time():
    target = MLModelVersion(version="2.0.0")
    session = FakeAsyncSession([FakeResult([]), FakeResult([target])])
    repo = MLModelVersionRepository(session)

    before = datetime.now(timezone.utc) - timedelta(seconds=1)
    await repo.set_active_version("2.0.0")

    assert target.deployed_at >= before


@pytest.mark.asyncio
async def test_get_all_versions_returns_every_version():
    versions = [MLModelVersion(version="2.0.0"), MLModelVersion(version="1.0.0")]
    repo = MLModelVersionRepository(FakeAsyncSession([FakeResult(versions)]))

    assert await repo.get_all_versions() == versions
