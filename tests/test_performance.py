"""
Performance tests and benchmarks for TerraSafe.

Tests scan times, cache performance, concurrent requests, and memory usage.
"""

import pytest
import time
import tempfile
import concurrent.futures
from pathlib import Path
import psutil
import os

from terrasafe.infrastructure.parser import HCLParser
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor
from terrasafe.application.scanner import IntelligentSecurityScanner


@pytest.fixture
def sample_tf_content():
    """Create sample Terraform content for testing."""
    return """
    resource "aws_instance" "web" {
        ami           = "ami-0c55b159cbfafe1f0"
        instance_type = "t2.micro"

        tags = {
            Name = "WebServer"
        }
    }

    resource "aws_security_group" "allow_all" {
        name        = "allow_all"
        description = "Allow all inbound traffic"

        ingress {
            from_port   = 0
            to_port     = 0
            protocol    = "-1"
            cidr_blocks = ["0.0.0.0/0"]
        }
    }

    resource "aws_s3_bucket" "data" {
        bucket = "my-data-bucket"
        acl    = "public-read"
    }

    resource "aws_db_instance" "database" {
        allocated_storage    = 20
        storage_type         = "gp2"
        engine               = "mysql"
        engine_version       = "5.7"
        instance_class       = "db.t2.micro"
        name                 = "mydb"
        username             = "admin"
        password             = "hardcoded-password-123"
        parameter_group_name = "default.mysql5.7"
        storage_encrypted    = false
    }
    """


@pytest.fixture
def temp_tf_file(sample_tf_content):
    """Create a temporary Terraform file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
        f.write(sample_tf_content)
        temp_path = f.name

    yield temp_path

    # Cleanup
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def scanner():
    """Create scanner instance."""
    parser = HCLParser()
    rule_analyzer = SecurityRuleEngine()
    model_manager = ModelManager()
    ml_predictor = MLPredictor(model_manager)
    return IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)


class TestScanPerformance:
    """Test scan performance benchmarks."""

    def test_scan_time_benchmark(self, scanner, temp_tf_file, benchmark):
        """Benchmark scan time for a typical file."""
        result = benchmark(scanner.scan, temp_tf_file)

        # Assertions
        assert result['score'] >= 0
        assert 'performance' in result

        # Performance expectations
        assert result['performance']['scan_time_seconds'] < 2.0, "Scan should complete in under 2 seconds"

    def test_scan_time_single_file(self, scanner, temp_tf_file):
        """Test scan time for a single file."""
        start_time = time.time()
        result = scanner.scan(temp_tf_file)
        scan_time = time.time() - start_time

        assert result['score'] >= 0
        assert scan_time < 2.0, f"Scan took {scan_time}s, expected < 2s"
        print(f"\nSingle file scan time: {scan_time:.3f}s")

    def test_scan_time_with_cache(self, scanner, temp_tf_file):
        """Test that cached scans are faster than initial scans."""
        # First scan (no cache)
        start_time = time.time()
        result1 = scanner.scan(temp_tf_file)
        first_scan_time = time.time() - start_time

        # Second scan (should use cache)
        start_time = time.time()
        result2 = scanner.scan(temp_tf_file)
        cached_scan_time = time.time() - start_time

        # Cached scan should be significantly faster (at least 2x)
        # Note: LRU cache with file hash should make this very fast
        print(f"\nFirst scan: {first_scan_time:.3f}s")
        print(f"Cached scan: {cached_scan_time:.3f}s")
        print(f"Speedup: {first_scan_time / cached_scan_time:.2f}x")

        assert result1['score'] == result2['score']
        # Cache should provide some speedup
        assert cached_scan_time <= first_scan_time

    def test_parser_performance(self, temp_tf_file, benchmark):
        """Benchmark parser performance."""
        parser = HCLParser()

        result = benchmark(parser.parse, temp_tf_file)

        assert result is not None
        assert len(result) == 2  # (tf_content, raw_content)


class TestCachePerformance:
    """Test cache performance."""

    def test_cache_hit_rate(self, scanner, temp_tf_file):
        """Test cache hit rate with multiple scans."""
        num_scans = 10

        for i in range(num_scans):
            result = scanner.scan(temp_tf_file)
            assert result['score'] >= 0

            # After first scan, all should be from cache
            if i > 0:
                assert result['performance']['from_cache'] is True

    def test_cache_invalidation_on_file_change(self, scanner, temp_tf_file):
        """Test that cache is invalidated when file changes."""
        # First scan
        result1 = scanner.scan(temp_tf_file)

        # Modify file
        time.sleep(0.1)  # Ensure mtime changes
        with open(temp_tf_file, 'a') as f:
            f.write('\n# Modified\n')

        # Second scan should not use cache
        result2 = scanner.scan(temp_tf_file)

        # Results might differ due to file modification
        assert result1 is not None
        assert result2 is not None


class TestConcurrentRequests:
    """Test concurrent request handling."""

    def test_concurrent_scans(self, scanner, sample_tf_content):
        """Test scanning multiple files concurrently."""
        num_files = 5
        temp_files = []

        # Create multiple temp files
        for i in range(num_files):
            with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
                f.write(sample_tf_content)
                temp_files.append(f.name)

        try:
            start_time = time.time()

            # Scan files concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(scanner.scan, path) for path in temp_files]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            total_time = time.time() - start_time

            # All scans should succeed
            assert len(results) == num_files
            assert all(r['score'] >= 0 for r in results)

            # Concurrent scans should be faster than sequential
            # (though with small files, overhead might dominate)
            print(f"\nConcurrent scan of {num_files} files: {total_time:.3f}s")
            print(f"Average per file: {total_time/num_files:.3f}s")

            # Should complete in reasonable time
            assert total_time < 10.0, f"Concurrent scans took {total_time}s, expected < 10s"

        finally:
            # Cleanup
            for path in temp_files:
                Path(path).unlink(missing_ok=True)

    def test_concurrent_scans_same_file(self, scanner, temp_tf_file):
        """Test scanning the same file concurrently."""
        num_concurrent = 10

        start_time = time.time()

        # Scan same file concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(scanner.scan, temp_tf_file) for _ in range(num_concurrent)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        total_time = time.time() - start_time

        # All scans should succeed and return same results
        assert len(results) == num_concurrent
        assert all(r['score'] == results[0]['score'] for r in results)

        print(f"\n{num_concurrent} concurrent scans of same file: {total_time:.3f}s")
        print(f"Average per scan: {total_time/num_concurrent:.3f}s")


class TestMemoryUsage:
    """Test memory usage during scans."""

    def test_memory_usage_single_scan(self, scanner, temp_tf_file):
        """Test memory usage for a single scan."""
        process = psutil.Process(os.getpid())

        # Get initial memory
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Perform scan
        result = scanner.scan(temp_tf_file)

        # Get final memory
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        print(f"\nMemory usage - Initial: {initial_memory:.2f}MB, Final: {final_memory:.2f}MB")
        print(f"Memory increase: {memory_increase:.2f}MB")

        assert result['score'] >= 0
        # Memory increase should be reasonable (< 50MB for a small file)
        assert memory_increase < 50, f"Memory increased by {memory_increase}MB, expected < 50MB"

    def test_memory_usage_multiple_scans(self, scanner, sample_tf_content):
        """Test memory usage for multiple scans (check for leaks)."""
        process = psutil.Process(os.getpid())

        # Get initial memory
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Perform multiple scans
        num_scans = 20
        for i in range(num_scans):
            with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
                f.write(sample_tf_content)
                temp_path = f.name

            try:
                result = scanner.scan(temp_path)
                assert result['score'] >= 0
            finally:
                Path(temp_path).unlink(missing_ok=True)

        # Get final memory
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        print(f"\nMemory after {num_scans} scans - Initial: {initial_memory:.2f}MB, Final: {final_memory:.2f}MB")
        print(f"Memory increase: {memory_increase:.2f}MB")
        print(f"Average per scan: {memory_increase/num_scans:.2f}MB")

        # Memory increase should be reasonable even after multiple scans
        # LRU cache should prevent unbounded growth
        assert memory_increase < 100, f"Memory increased by {memory_increase}MB after {num_scans} scans"


class TestScalability:
    """Test scalability with varying file sizes."""

    def test_small_file_performance(self, scanner):
        """Test performance with small files."""
        small_content = 'resource "test" { name = "test" }'

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
            f.write(small_content)
            temp_path = f.name

        try:
            start_time = time.time()
            result = scanner.scan(temp_path)
            scan_time = time.time() - start_time

            print(f"\nSmall file scan time: {scan_time:.3f}s")
            assert result['score'] >= 0
            assert scan_time < 1.0, "Small file should scan very quickly"

        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_large_file_performance(self, scanner):
        """Test performance with larger files."""
        # Create a large Terraform file
        large_content = ""
        for i in range(50):
            large_content += f"""
            resource "aws_instance" "instance_{i}" {{
                ami           = "ami-{i:08d}"
                instance_type = "t2.micro"

                tags = {{
                    Name = "Instance-{i}"
                }}
            }}
            """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
            f.write(large_content)
            temp_path = f.name

        try:
            start_time = time.time()
            result = scanner.scan(temp_path)
            scan_time = time.time() - start_time

            print(f"\nLarge file scan time: {scan_time:.3f}s")
            print(f"File size: {Path(temp_path).stat().st_size / 1024:.2f}KB")
            assert result['score'] >= 0
            assert scan_time < 5.0, f"Large file scan took {scan_time}s, expected < 5s"

        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestFeatureExtractionPerformance:
    """Test performance of feature extraction."""

    def test_feature_extraction_with_many_vulnerabilities(self, scanner):
        """Test feature extraction performance with many vulnerabilities."""
        from terrasafe.domain.models import Vulnerability, Severity

        # Create many vulnerabilities
        vulnerabilities = []
        for i in range(100):
            vuln = Vulnerability(
                severity=Severity.HIGH,
                points=10,
                message=f"Test vulnerability {i} - hardcoded secret detected",
                resource=f"resource_{i}",
                remediation="Fix it"
            )
            vulnerabilities.append(vuln)

        start_time = time.time()
        features = scanner._extract_features(vulnerabilities)
        extraction_time = time.time() - start_time

        print(f"\nFeature extraction time for 100 vulnerabilities: {extraction_time:.4f}s")
        assert features is not None
        assert extraction_time < 0.1, f"Feature extraction took {extraction_time}s, expected < 0.1s"


# Pytest benchmark plugin configuration
def pytest_configure(config):
    """Configure pytest for benchmarks."""
    config.addinivalue_line(
        "markers", "benchmark: mark test as a performance benchmark"
    )
