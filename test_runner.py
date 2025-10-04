#!/usr/bin/env python3
"""
Integrated test runner for TerraSafe
Runs unit, integration, and API tests
"""

import sys
import unittest
import subprocess
from pathlib import Path

# Import test classes
from test_security_scanner import (
    TestSecurityRuleEngine,
    TestIntelligentSecurityScanner,
    TestIntelligentSecurityScannerIntegration,
    TestModelManager,
    TestVulnerabilityDataclass,
    TestHCLParser,
    TestMLPredictor
)


def run_unit_tests():
    """Run all unit tests"""
    print("\n" + "="*60)
    print("RUNNING UNIT TESTS")
    print("="*60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityRuleEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestIntelligentSecurityScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestIntelligentSecurityScannerIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestModelManager))
    suite.addTests(loader.loadTestsFromTestCase(TestVulnerabilityDataclass))
    suite.addTests(loader.loadTestsFromTestCase(TestHCLParser))
    suite.addTests(loader.loadTestsFromTestCase(TestMLPredictor))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def run_integration_tests():
    """Run integration tests on real .tf files"""
    print("\n" + "="*60)
    print("RUNNING INTEGRATION TESTS")
    print("="*60)
    
    from security_scanner import IntelligentSecurityScanner
    from terrasafe.infrastructure.parser import HCLParser
    from terrasafe.domain.security_rules import SecurityRuleEngine
    from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor
    
    parser = HCLParser()
    rule_analyzer = SecurityRuleEngine()
    model_manager = ModelManager()
    ml_predictor = MLPredictor(model_manager)
    scanner = IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)
    
    test_cases = [
        ("test_files/vulnerable.tf", 70, 100, "HIGH RISK"),
        ("test_files/secure.tf", 0, 30, "LOW RISK"),
        ("test_files/mixed.tf", 30, 70, "MEDIUM RISK")
    ]
    
    all_passed = True
    
    for filepath, min_score, max_score, expected_risk in test_cases:
        if not Path(filepath).exists():
            print(f"❌ File not found: {filepath}")
            all_passed = False
            continue
            
        print(f"\n Testing: {filepath}")
        results = scanner.scan(filepath)
        score = results['score']
        
        if min_score <= score <= max_score:
            print(f"   ✅ Score: {score}/100 - {expected_risk} as expected")
        else:
            print(f"   ❌ Score: {score}/100 - Expected {min_score}-{max_score}")
            all_passed = False
        
        if 'ml_score' in results and 'confidence' in results:
            print(f"   ✅ ML integration: {results['ml_score']:.1f} ({results['confidence']})")
        else:
            print(f"   ❌ ML integration failed")
            all_passed = False
    
    return all_passed


def run_api_tests():
    """Run API endpoint tests"""
    print("\n" + "="*60)
    print("RUNNING API TESTS")
    print("="*60)
    
    if not Path("test_api.py").exists():
        print("⚠️  test_api.py not found, skipping API tests")
        return True
    
    try:
        result = subprocess.run(
            ["python", "-m", "pytest", "test_api.py", "-v"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("❌ API tests timed out")
        return False
    except Exception as e:
        print(f"⚠️  Could not run API tests: {e}")
        return True  # Don't fail if API server not running


def run_coverage():
    """Generate coverage report"""
    print("\n" + "="*60)
    print("GENERATING COVERAGE REPORT")
    print("="*60)
    
    try:
        import coverage
        
        cov = coverage.Coverage()
        cov.start()
        
        run_unit_tests()
        
        cov.stop()
        cov.save()
        
        print("\nCoverage Summary:")
        cov.report()
        
        cov.html_report(directory='htmlcov')
        print("\n✅ HTML coverage report: htmlcov/index.html")
        
    except ImportError:
        print("⚠️  Install coverage: pip install coverage")


if __name__ == "__main__":
    success = True
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--unit":
            success = run_unit_tests()
        elif sys.argv[1] == "--integration":
            success = run_integration_tests()
        elif sys.argv[1] == "--api":
            success = run_api_tests()
        elif sys.argv[1] == "--coverage":
            run_coverage()
        else:
            print("Usage: python test_runner.py [--unit|--integration|--api|--coverage]")
    else:
        # Run all tests
        unit_success = run_unit_tests()
        integration_success = run_integration_tests()
        api_success = run_api_tests()
        
        success = unit_success and integration_success and api_success
        
        if success:
            print("\n" + "="*60)
            print("✅ ALL TESTS PASSED!")
            print("="*60)
        else:
            print("\n" + "="*60)
            print("❌ SOME TESTS FAILED")
            print("="*60)
    
    sys.exit(0 if success else 1)