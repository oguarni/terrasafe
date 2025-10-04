"""Scanner orchestration - Application layer"""
import time
import numpy as np
from pathlib import Path
from typing import Dict, Any, List

from ..domain.models import Vulnerability
from ..domain.security_rules import SecurityRuleEngine
from ..infrastructure.parser import HCLParser
from ..infrastructure.ml_model import MLPredictor

class IntelligentSecurityScanner:
    """Orchestrates the scanning process"""
    
    def __init__(
        self, 
        parser: HCLParser,
        rule_analyzer: SecurityRuleEngine,
        ml_predictor: MLPredictor
    ):
        self.parser = parser
        self.rule_analyzer = rule_analyzer
        self.ml_predictor = ml_predictor
    
    # Copy scan() and helper methods
