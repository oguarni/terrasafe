#!/usr/bin/env python3
"""CLI entry point for TerraSafe"""
import sys
from pathlib import Path

from .infrastructure.parser import HCLParser
from .infrastructure.ml_model import ModelManager, MLPredictor
from .domain.security_rules import SecurityRuleEngine
from .application.scanner import IntelligentSecurityScanner

def main():
    """Main entry point with dependency injection"""
    if len(sys.argv) != 2:
        print("Usage: python -m terrasafe.cli <terraform_file.tf>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    # Dependency Injection (Clean Architecture)
    parser = HCLParser()
    rule_analyzer = SecurityRuleEngine()
    model_manager = ModelManager()
    ml_predictor = MLPredictor(model_manager)
    
    scanner = IntelligentSecurityScanner(
        parser=parser,
        rule_analyzer=rule_analyzer,
        ml_predictor=ml_predictor
    )
    
    print("🔐 TerraSafe - Scanning...")
    results = scanner.scan(filepath)
    
    # Print results
    print(f"Risk Score: {results['score']}/100")
    sys.exit(0 if results['score'] < 70 else 1)

if __name__ == "__main__":
    main()
