#!/usr/bin/env python3
"""
Integrated test runner for TerraSafe
Runs both unit tests and integration tests
"""

import sys
import unittest
from pathlib import Path

# Import test modules
from test_security_scanner import (
    TestSecurityRuleEngine,
    TestModelManager, 
    TestIntelligentSecurityScanner,
    TestVulnerabilityDataclass
)


def run_unit_tests():
    """Run all unit tests with coverage"""
    print("\n" + "="*60)
    print("RUNNING UNIT TESTS")
    print("="*60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityRuleEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestModelManager))
    suite.addTests(loader.loadTestsFromTestCase(TestIntelligentSecurityScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestVulnerabilityDataclass))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return success status
    return result.wasSuccessful()


def run_integration_tests():
    """Run integration tests on real .tf files"""
    print("\n" + "="*60)
    print("RUNNING INTEGRATION TESTS")
    print("="*60)
    
    from security_scanner import IntelligentSecurityScanner
    
    scanner = IntelligentSecurityScanner()
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
        
        # Validate score range
        if min_score <= score <= max_score:
            print(f"   ✅ Score: {score}/100 - {expected_risk} as expected")
        else:
            print(f"   ❌ Score: {score}/100 - Expected {min_score}-{max_score}")
            all_passed = False
        
        # Validate ML model integration
        if 'ml_score' in results and 'confidence' in results:
            print(f"   ✅ ML integration working: {results['ml_score']:.1f} ({results['confidence']})")
        else:
            print(f"   ❌ ML integration failed")
            all_passed = False
    
    return all_passed


def generate_coverage_report():
    """Generate test coverage report"""
    try:
        import coverage
        print("\n" + "="*60)
        print("GENERATING COVERAGE REPORT")
        print("="*60)
        
        # Run coverage analysis
        cov = coverage.Coverage()
        cov.start()
        
        # Import modules to test
        import security_scanner
        
        # Run tests under coverage
        run_unit_tests()
        
        cov.stop()
        cov.save()
        
        # Generate report
        print("\nCoverage Summary:")
        cov.report()
        
        # Generate HTML report
        cov.html_report(directory='htmlcov')
        print("\n✅ HTML coverage report saved to htmlcov/index.html")
        
    except ImportError:
        print("⚠️  Install coverage: pip install coverage")


if __name__ == "__main__":
    success = True
    
    # Run based on arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--unit":
            success = run_unit_tests()
        elif sys.argv[1] == "--integration":
            success = run_integration_tests()
        elif sys.argv[1] == "--coverage":
            generate_coverage_report()
        else:
            print("Usage: python test_runner.py [--unit|--integration|--coverage]")
    else:
        # Run all tests
        unit_success = run_unit_tests()
        integration_success = run_integration_tests()
        success = unit_success and integration_success
        
        if success:
            print("\n" + "="*60)
            print("✅ ALL TESTS PASSED!")
            print("="*60)
        else:
            print("\n" + "="*60)
            print("❌ SOME TESTS FAILED")
            print("="*60)
    
    sys.exit(0 if success else 1)