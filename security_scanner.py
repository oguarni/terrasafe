#!/usr/bin/env python3
"""
TerraSafe - Intelligent Terraform Security Scanner
Main application entry point.
"""

import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import numpy as np

import re
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Tuple
import hcl2
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ModelNotTrainedError(Exception):
    """Raised when model operations are attempted on an untrained model."""
    pass


class TerraformParseError(Exception):
    """Raised when Terraform file parsing fails."""
    pass


class Severity(Enum):
    """Security severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Vulnerability:
    """Represents a security vulnerability"""
    severity: Severity
    points: int
    message: str
    resource: str
    remediation: str = ""


class SecurityRuleEngine:
    """Rule-based security detection engine"""
    
    def __init__(self):
        self.vulnerabilities = []
    
    def check_open_security_groups(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for security groups with open access (0.0.0.0/0)"""
        vulns = []
        
        if 'resource' not in tf_content:
            return vulns
        
        for resource in tf_content.get('resource', []):
            if 'aws_security_group' in resource:
                sg_list = resource['aws_security_group']
                # Handle both list and dict formats
                if isinstance(sg_list, list):
                    sg_items = sg_list
                else:
                    sg_items = [sg_list]
                
                for sg_item in sg_items:
                    if isinstance(sg_item, dict):
                        for sg_name, sg_config in sg_item.items():
                            # Check ingress rules
                            for ingress in sg_config.get('ingress', []):
                                cidr_blocks = ingress.get('cidr_blocks', [])
                                from_port = ingress.get('from_port', 0)
                                
                                if '0.0.0.0/0' in cidr_blocks:
                                    if from_port == 22:
                                        vulns.append(Vulnerability(
                                            severity=Severity.CRITICAL,
                                            points=30,
                                            message=f"[CRITICAL] Open security group - SSH port 22 exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict SSH access to specific IP ranges"
                                        ))
                                    elif from_port == 3389:
                                        vulns.append(Vulnerability(
                                            severity=Severity.CRITICAL,
                                            points=30,
                                            message=f"[CRITICAL] Open security group - RDP port 3389 exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict RDP access to specific IP ranges"
                                        ))
                                    elif from_port == 80 or from_port == 443:
                                        vulns.append(Vulnerability(
                                            severity=Severity.MEDIUM,
                                            points=10,
                                            message=f"[MEDIUM] HTTP/HTTPS port {from_port} open to internet",
                                            resource=sg_name,
                                            remediation="Consider using a CDN or WAF for public web services"
                                        ))
                                    else:
                                        vulns.append(Vulnerability(
                                            severity=Severity.HIGH,
                                            points=20,
                                            message=f"[HIGH] Port {from_port} exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict access to specific IP ranges"
                                        ))
        
        return vulns
    
    def check_hardcoded_secrets(self, raw_content: str) -> List[Vulnerability]:
        """Check for hardcoded passwords and secrets using regex"""
        vulns = []
        
        # Pattern for hardcoded passwords (not variables)
        password_pattern = r'password\s*=\s*"([^"]+)"'
        matches = re.finditer(password_pattern, raw_content, re.IGNORECASE)
        
        for match in matches:
            password_value = match.group(1)
            # Skip if it's a variable reference
            if not password_value.startswith('var.') and not password_value.startswith('${'):
                vulns.append(Vulnerability(
                    severity=Severity.CRITICAL,
                    points=30,
                    message=f"[CRITICAL] Hardcoded password detected",
                    resource="Database/Instance",
                    remediation="Use variables or secrets manager for sensitive data"
                ))
        
        # Check for API keys and tokens
        secret_patterns = [
            (r'api_key\s*=\s*"([^"]+)"', "API key"),
            (r'secret_key\s*=\s*"([^"]+)"', "Secret key"),
            (r'token\s*=\s*"([^"]+)"', "Token")
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, raw_content, re.IGNORECASE)
            for match in matches:
                value = match.group(1)
                if not value.startswith('var.') and not value.startswith('${'):
                    vulns.append(Vulnerability(
                        severity=Severity.CRITICAL,
                        points=30,
                        message=f"[CRITICAL] Hardcoded {secret_type} detected",
                        resource="Configuration",
                        remediation="Use environment variables or secrets manager"
                    ))
        
        return vulns
    
    def check_encryption(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for unencrypted storage resources"""
        vulns = []
        
        if 'resource' not in tf_content:
            return vulns
        
        for resource in tf_content.get('resource', []):
            # Check RDS instances
            if 'aws_db_instance' in resource:
                db_list = resource['aws_db_instance']
                if isinstance(db_list, list):
                    db_items = db_list
                else:
                    db_items = [db_list]
                    
                for db_item in db_items:
                    if isinstance(db_item, dict):
                        for db_name, db_config in db_item.items():
                            if not db_config.get('storage_encrypted', False):
                                vulns.append(Vulnerability(
                                    severity=Severity.HIGH,
                                    points=20,
                                    message=f"[HIGH] Unencrypted RDS instance",
                                    resource=db_name,
                                    remediation="Enable storage_encrypted = true"
                                ))
            
            # Check EBS volumes
            if 'aws_ebs_volume' in resource:
                vol_list = resource['aws_ebs_volume']
                if isinstance(vol_list, list):
                    vol_items = vol_list
                else:
                    vol_items = [vol_list]
                    
                for vol_item in vol_items:
                    if isinstance(vol_item, dict):
                        for vol_name, vol_config in vol_item.items():
                            if not vol_config.get('encrypted', False):
                                vulns.append(Vulnerability(
                                    severity=Severity.HIGH,
                                    points=20,
                                    message=f"[HIGH] Unencrypted EBS volume",
                                    resource=vol_name,
                                    remediation="Enable encrypted = true"
                                ))
        
        return vulns
    
    def check_public_s3(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for public S3 bucket configurations"""
        vulns = []
        
        if 'resource' not in tf_content:
            return vulns
        
        for resource in tf_content.get('resource', []):
            if 'aws_s3_bucket_public_access_block' in resource:
                bucket_list = resource['aws_s3_bucket_public_access_block']
                if isinstance(bucket_list, list):
                    bucket_items = bucket_list
                else:
                    bucket_items = [bucket_list]
                    
                for bucket_item in bucket_items:
                    if isinstance(bucket_item, dict):
                        for bucket_name, config in bucket_item.items():
                            public_settings = [
                                ('block_public_acls', config.get('block_public_acls', True)),
                                ('block_public_policy', config.get('block_public_policy', True)),
                                ('ignore_public_acls', config.get('ignore_public_acls', True)),
                                ('restrict_public_buckets', config.get('restrict_public_buckets', True))
                            ]
                            
                            public_count = sum(1 for _, value in public_settings if not value)
                            
                            if public_count >= 3:
                                vulns.append(Vulnerability(
                                    severity=Severity.HIGH,
                                    points=20,
                                    message=f"[HIGH] S3 bucket with public access enabled",
                                    resource=bucket_name,
                                    remediation="Enable all public access blocks"
                                ))
                            elif public_count > 0:
                                vulns.append(Vulnerability(
                                    severity=Severity.MEDIUM,
                                    points=10,
                                    message=f"[MEDIUM] S3 bucket with partial public access",
                                    resource=bucket_name,
                                    remediation="Review and restrict public access settings"
                                ))
        
        return vulns
    
    def analyze(self, tf_content: Dict, raw_content: str) -> List[Vulnerability]:
        """Run all security checks"""
        all_vulns = []
        
        # Run all checks
        all_vulns.extend(self.check_open_security_groups(tf_content))
        all_vulns.extend(self.check_hardcoded_secrets(raw_content))
        all_vulns.extend(self.check_encryption(tf_content))
        all_vulns.extend(self.check_public_s3(tf_content))
        
        return all_vulns


class HCLParser:
    """Handles parsing of HCL files."""
    def parse(self, filepath: str) -> Tuple[Dict[str, Any], str]:
        """
        Parses a Terraform file, with fallbacks.
        Raises TerraformParseError if parsing fails.
        """
        path = Path(filepath)
        if not path.exists():
            raise TerraformParseError(f"File not found: {filepath}")

        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw_content = f.read()
        except Exception as e:
            raise TerraformParseError(f"Cannot read file: {e}")

        try:
            tf_content = hcl2.loads(raw_content)
            return tf_content, raw_content
        except Exception as hcl_error:
            logger.debug(f"HCL2 parse failed: {hcl_error}")
            # Fallback to JSON parsing for .tf.json files
            try:
                tf_content = json.loads(raw_content)
                return tf_content, raw_content
            except json.JSONDecodeError:
                raise TerraformParseError(f"Invalid HCL or JSON syntax in {filepath}") from hcl_error


class ModelManager:
    """Manages ML model persistence and loading."""
    def __init__(self, model_dir: str = "models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        self.model_path = self.model_dir / "isolation_forest.pkl"
        self.scaler_path = self.model_dir / "scaler.pkl"
        self.metadata_path = self.model_dir / "training_metadata.json"

    def save_model(self, model: IsolationForest, scaler: StandardScaler, metadata: dict):
        """Save trained model, scaler, and metadata."""
        try:
            joblib.dump(model, self.model_path)
            joblib.dump(scaler, self.scaler_path)
            with open(self.metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"Model and metadata saved to {self.model_dir}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")

    def load_model(self) -> Tuple[IsolationForest, StandardScaler]:
        """Load saved model and scaler, raising an error if not found."""
        if not self.model_path.exists() or not self.scaler_path.exists():
            raise ModelNotTrainedError("Model or scaler file not found.")
        try:
            model = joblib.load(self.model_path)
            scaler = joblib.load(self.scaler_path)
            logger.info("Model loaded successfully")
            return model, scaler
        except Exception as e:
            raise ModelNotTrainedError(f"Error loading model: {e}") from e

    def model_exists(self) -> bool:
        """Check if saved model exists"""
        return self.model_path.exists() and self.scaler_path.exists()


class MLPredictor:
    """ML-based anomaly predictor."""
    def __init__(self, model_manager: ModelManager = None):
        self.model_manager = model_manager or ModelManager()
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._initialize_ml_model()

    def _initialize_ml_model(self):
        """Load an existing model or train a new one."""
        try:
            self.model, self.scaler = self.model_manager.load_model()
        except ModelNotTrainedError:
            logger.warning("No pre-trained model found. Training a new baseline model.")
            self._train_baseline_model()

    def predict_risk(self, features: np.ndarray) -> Tuple[float, str]:
        """Calculate risk score using the loaded ML model."""
        if self.model is None or self.scaler is None:
            raise ModelNotTrainedError("Model is not initialized.")
        
        try:
            scaled_features = self.scaler.transform(features)
            prediction = self.model.predict(scaled_features)[0]
            anomaly_score = self.model.decision_function(scaled_features)[0]

            # Enhanced risk score calculation
            if prediction == -1:  # Anomaly detected
                risk_score = min(100, max(50, 50 + abs(anomaly_score) * 100))
            else:  # Normal pattern
                risk_score = max(0, min(50, 50 - anomaly_score * 50))
            
            # Determine confidence based on distance from decision boundary
            if abs(anomaly_score) > 0.3:
                confidence = "HIGH"
            elif abs(anomaly_score) > 0.1:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
            
            logger.debug(f"ML Score: {risk_score:.1f}, Confidence: {confidence}, Anomaly: {anomaly_score:.3f}")
            return risk_score, confidence
        except Exception as e:
            logger.error(f"Error in ML scoring: {e}")
            return 50.0, "LOW"  # Return neutral score on error
    
    def _train_baseline_model(self):
        """Train and save a new baseline model with comprehensive patterns."""
        # Set seed for reproducibility
        np.random.seed(42)
        
        # Enhanced baseline patterns representing secure configurations
        # Features: [open_ports, secrets, public_access, unencrypted, resource_count]
        baseline_patterns = [
            # Fully secure configurations
            [0, 0, 0, 0, 5],   # Small secure microservice
            [0, 0, 0, 0, 10],  # Medium secure application
            [0, 0, 0, 0, 15],  # Large secure infrastructure
            [0, 0, 0, 0, 25],  # Enterprise secure setup
            [0, 0, 0, 0, 3],   # Minimal secure Lambda function
            
            # Web applications (acceptable public exposure)
            [1, 0, 0, 0, 8],   # Simple web app with HTTP
            [2, 0, 0, 0, 12],  # Web app with HTTP/HTTPS
            [2, 0, 1, 0, 20],  # E-commerce with CDN (public S3)
            [1, 0, 1, 0, 15],  # Static site with S3 hosting
            [2, 0, 2, 0, 30],  # Multi-region web platform
            
            # Development environments (slightly relaxed)
            [1, 0, 0, 1, 6],   # Dev env with one unencrypted volume
            [2, 0, 0, 1, 10],  # Staging with test data
            [1, 0, 1, 1, 8],   # QA environment
            [0, 0, 0, 2, 12],  # Test cluster with temp storage
            
            # Microservices architectures
            [3, 0, 0, 0, 40],  # Service mesh with multiple endpoints
            [4, 0, 1, 0, 50],  # Kubernetes cluster with ingress
            [2, 0, 0, 0, 35],  # Docker swarm setup
            [3, 0, 2, 0, 45],  # Multi-service with CDN
        ]
        
        baseline_features = np.array(baseline_patterns)
        
        # Advanced augmentation with realistic variations
        augmented_data = baseline_features.copy()
        
        # Add noise variations for each pattern
        for pattern in baseline_features:
            for _ in range(3):  # Create 3 variations per pattern
                noise = np.random.normal(0, 0.15, 5)
                augmented = pattern + noise
                augmented = np.maximum(augmented, 0)  # Ensure non-negative
                # Round discrete features
                augmented = np.round(augmented)
                augmented_data = np.vstack([augmented_data, augmented])
        
        # Add edge cases representing acceptable boundaries
        edge_cases = np.array([
            [5, 0, 0, 0, 60],  # Large microservices
            [0, 0, 5, 0, 40],  # Content delivery network
            [3, 0, 3, 2, 50],  # Legacy migration
            [0, 0, 0, 3, 25],  # Development cluster
            [6, 0, 2, 0, 70],  # API gateway with multiple services
        ])
        
        augmented_data = np.vstack([augmented_data, edge_cases])
        
        # Train scaler and model
        self.scaler = StandardScaler()
        scaled_features = self.scaler.fit_transform(augmented_data)
        
        # Configure Isolation Forest with optimized parameters
        self.model = IsolationForest(
            contamination=0.05,  # Expect 5% anomalies
            random_state=42,
            n_estimators=150,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1
        )
        
        self.model.fit(scaled_features)
        
        # Prepare training metadata
        training_stats = {
            'total_samples': len(augmented_data),
            'secure_patterns': len(baseline_patterns),
            'augmented_samples': len(augmented_data) - len(baseline_patterns),
            'feature_ranges': {
                'open_ports': {'min': int(augmented_data[:, 0].min()), 'max': int(augmented_data[:, 0].max())},
                'hardcoded_secrets': {'min': int(augmented_data[:, 1].min()), 'max': int(augmented_data[:, 1].max())},
                'public_access': {'min': int(augmented_data[:, 2].min()), 'max': int(augmented_data[:, 2].max())},
                'unencrypted_storage': {'min': int(augmented_data[:, 3].min()), 'max': int(augmented_data[:, 3].max())},
                'total_resources': {'min': int(augmented_data[:, 4].min()), 'max': int(augmented_data[:, 4].max())},
            },
            'model_parameters': {
                'contamination': 0.05,
                'n_estimators': 150,
                'random_state': 42
            }
        }
        
        # Save model with metadata
        self.model_manager.save_model(self.model, self.scaler, training_stats)
        logger.info(f"New model trained and saved with {len(augmented_data)} samples.")
        print(f"✅ Enhanced ML model trained successfully with {len(augmented_data)} samples")


class IntelligentSecurityScanner:
    """Orchestrates the scanning process."""

    def __init__(self, parser: HCLParser, rule_analyzer: SecurityRuleEngine, ml_predictor: MLPredictor):
        self.parser = parser
        self.rule_analyzer = rule_analyzer
        self.ml_predictor = ml_predictor

    def scan(self, filepath: str) -> Dict[str, Any]:
        """Main scanning method with performance metrics and improved error handling."""
        start_time = time.time()
        try:
            tf_content, raw_content = self.parser.parse(filepath)
            
            vulnerabilities = self.rule_analyzer.analyze(tf_content, raw_content)
            
            rule_score = min(100, sum(v.points for v in vulnerabilities))
            
            features = self._extract_features(vulnerabilities)
            ml_score, confidence = self.ml_predictor.predict_risk(features)
            
            final_score = int(0.6 * rule_score + 0.4 * ml_score)
            
            scan_duration = round(time.time() - start_time, 3)
            file_size_kb = round(Path(filepath).stat().st_size / 1024, 2)

            return {
                'file': filepath,
                'score': final_score,
                'rule_based_score': rule_score,
                'ml_score': ml_score,
                'confidence': confidence,
                'vulnerabilities': [self._vulnerability_to_dict(v) for v in vulnerabilities],
                'summary': self._summarize_vulns(vulnerabilities),
                'features_analyzed': self._format_features(features),
                'performance': {
                    'scan_time_seconds': scan_duration,
                    'file_size_kb': file_size_kb
                }
            }
        except (TerraformParseError, FileNotFoundError) as e:
            logger.error(f"Failed to scan {filepath}: {e}")
            return {'score': -1, 'error': str(e)}
        except Exception as e:
            logger.error(f"An unexpected error occurred during scan: {e}", exc_info=True)
            return {'score': -1, 'error': f"An unexpected error occurred: {e}"}
            
    def _extract_features(self, vulnerabilities: List[Vulnerability]) -> np.ndarray:
        """Extracts feature vector from vulnerabilities for ML model."""
        features = {'open_ports': 0, 'hardcoded_secrets': 0, 'public_access': 0, 'unencrypted_storage': 0, 'total_resources': 5}
        for vuln in vulnerabilities:
            msg = vuln.message.lower()
            if 'open security group' in msg or 'exposed to internet' in msg:
                features['open_ports'] += 1
            elif 'hardcoded' in msg or 'secret' in msg:
                features['hardcoded_secrets'] += 1
            elif 's3 bucket' in msg and 'public' in msg:
                features['public_access'] += 1
            elif 'unencrypted' in msg:
                features['unencrypted_storage'] += 1
        return np.array(list(features.values())).reshape(1, -1)
    
    def _summarize_vulns(self, vulns: List[Vulnerability]) -> Dict[str, int]:
        summary = {s.name.lower(): 0 for s in Severity}
        for v in vulns:
            summary[v.severity.name.lower()] += 1
        return summary

    def _format_features(self, features: np.ndarray) -> Dict[str, int]:
        feature_names = ['open_ports', 'hardcoded_secrets', 'public_access', 'unencrypted_storage', 'total_resources']
        return {name: int(val) for name, val in zip(feature_names, features[0])}
    
    def _vulnerability_to_dict(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert Vulnerability dataclass to dictionary for JSON serialization."""
        return {
            'severity': vuln.severity.value,
            'points': vuln.points,
            'message': vuln.message,
            'resource': vuln.resource,
            'remediation': vuln.remediation
        }


def format_results_for_display(results: Dict[str, Any]) -> str:
    """Formats scan results for console output."""
    if results['score'] == -1:
        return f"\n❌ Error scanning file: {results.get('error', 'Unknown error')}"

    output = ["\n" + "="*60, "🔍 TERRAFORM SECURITY SCAN RESULTS", "="*60, f"📁 File: {results['file']}", "-"*60]

    score = results['score']
    status = "✅ LOW RISK"
    color = "\033[92m" # Green
    if score >= 70:
        status, color = "❌ CRITICAL RISK", "\033[91m" # Red
    elif score >= 40:
        status, color = "⚠️  MEDIUM RISK", "\033[93m" # Yellow
    
    output.append(f"\n{status}")
    output.append(f"{color}📊 Final Risk Score: {score}/100\033[0m")
    output.append(f"├─ Rule-based Score: {results['rule_based_score']}/100")
    output.append(f"├─ ML Anomaly Score: {results['ml_score']:.1f}/100")
    output.append(f"└─ Confidence: {results['confidence']}")

    # Feature analysis (if available)
    if 'features_analyzed' in results:
        output.append(f"\n🔬 Feature Analysis:")
        features = results['features_analyzed']
        output.append(f"   Open Ports: {features['open_ports']}")
        output.append(f"   Hardcoded Secrets: {features['hardcoded_secrets']}")
        output.append(f"   Public Access: {features['public_access']}")
        output.append(f"   Unencrypted Storage: {features['unencrypted_storage']}")

    # Performance metrics
    if 'performance' in results:
        perf = results['performance']
        output.append(f"\n⏱️  Performance:")
        output.append(f"   Scan Time: {perf['scan_time_seconds']}s")
        output.append(f"   File Size: {perf['file_size_kb']} KB")

    if results['vulnerabilities']:
        output.append("\n🚨 Detected Vulnerabilities:")
        output.append("-" * 60)
        for v in results['vulnerabilities']:
            output.append(f"\n{v['message']}")
            output.append(f"   📍 Resource: {v['resource']}")
            if v['remediation']:
                output.append(f"   💡 Fix: {v['remediation']}")
    else:
        output.append("\n\033[92m✅ No security issues detected!\033[0m")
        output.append("✓ All resources properly configured")
        output.append("✓ Encryption enabled where required")
        output.append("✓ Network access properly restricted")

    output.append("\n" + "="*60)
    return "\n".join(output)


def main():
    """Main entry point with unique output and scan history tracking."""
    if len(sys.argv) != 2:
        print("Usage: python security_scanner.py <terraform_file.tf>")
        print("\nExample:")
        print("  python security_scanner.py test_files/vulnerable.tf")
        sys.exit(1)

    filepath = sys.argv[1]

    # Dependency Injection
    parser = HCLParser()
    rule_analyzer = SecurityRuleEngine()
    model_manager = ModelManager()
    ml_predictor = MLPredictor(model_manager)
    scanner = IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)

    print("🔐 TerraSafe - Intelligent Terraform Security Scanner")
    print("🤖 Using hybrid approach: Rules (60%) + ML Anomaly Detection (40%)")

    results = scanner.scan(filepath)

    print(format_results_for_display(results))

    # Construct unique output filename (scan_results_<stem>.json)
    input_stem = Path(filepath).stem
    json_output = Path(f"scan_results_{input_stem}.json")

    # Persist individual scan result
    try:
        with open(json_output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n📄 Scan results saved to {json_output}")
    except Exception as e:
        logger.error(f"Failed writing scan output {json_output}: {e}")

    # Append to consolidated history (scan_history.json)
    history_path = Path("scan_history.json")
    # Add timestamp (ISO8601) without mutating original dict externally
    results_with_meta = dict(results)
    results_with_meta['timestamp'] = datetime.utcnow().isoformat() + 'Z'
    try:
        if history_path.exists():
            with open(history_path, 'r') as hf:
                history = json.load(hf)
                if not isinstance(history, dict) or 'scans' not in history:
                    history = {"scans": []}
        else:
            history = {"scans": []}
        history['scans'].append(results_with_meta)
        with open(history_path, 'w') as hf:
            json.dump(history, hf, indent=2, default=str)
        print(f"📊 History updated in {history_path}")
    except Exception as e:
        logger.error(f"Failed updating history file: {e}")

    # Exit code based on risk (unchanged semantics)
    if results['score'] == -1:
        sys.exit(2)  # Error
    elif results['score'] >= 70:
        sys.exit(1)  # High risk
    sys.exit(0)  # Acceptable risk


def main_with_args():
    """Argparse-enabled entry point supporting custom output and history toggle."""
    import argparse

    parser_cli = argparse.ArgumentParser(description='TerraSafe - Intelligent Terraform Security Scanner')
    parser_cli.add_argument('file', help='Terraform file to scan')
    parser_cli.add_argument('-o', '--output', help='Output JSON file (default: scan_results_<filename>.json)')
    parser_cli.add_argument('--no-history', action='store_true', help='Do not append to scan_history.json')
    parser_cli.add_argument('--fail-threshold', type=int, default=70, help='Risk threshold to trigger non-zero exit (default: 70)')
    args = parser_cli.parse_args()

    parser = HCLParser()
    rule_analyzer = SecurityRuleEngine()
    model_manager = ModelManager()
    ml_predictor = MLPredictor(model_manager)
    scanner = IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)

    results = scanner.scan(args.file)
    print(format_results_for_display(results))

    input_stem = Path(args.file).stem
    json_output = Path(args.output) if args.output else Path(f"scan_results_{input_stem}.json")
    try:
        with open(json_output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n📄 Scan results saved to {json_output}")
    except Exception as e:
        logger.error(f"Failed writing scan output {json_output}: {e}")

    if not args.no_history:
        history_path = Path("scan_history.json")
        results_hist = dict(results)
        results_hist['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        try:
            if history_path.exists():
                with open(history_path, 'r') as hf:
                    history = json.load(hf)
                    if not isinstance(history, dict) or 'scans' not in history:
                        history = {"scans": []}
            else:
                history = {"scans": []}
            history['scans'].append(results_hist)
            with open(history_path, 'w') as hf:
                json.dump(history, hf, indent=2, default=str)
            print(f"📊 History updated in {history_path}")
        except Exception as e:
            logger.error(f"Failed updating history file: {e}")

    # Exit logic with configurable threshold
    if results['score'] == -1:
        sys.exit(2)
    elif results['score'] >= args.fail_threshold:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()