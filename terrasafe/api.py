#!/usr/bin/env python3
"""FastAPI REST API for TerraSafe with rate limiting and async support"""
import tempfile
import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Security, Depends
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import logging

from terrasafe.infrastructure.parser import HCLParser
from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.application.scanner import IntelligentSecurityScanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Key Authentication
API_KEY = os.getenv("TERRASAFE_API_KEY", "change-me-in-production")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    """
    Verify API key from request header

    Args:
        api_key: API key from X-API-Key header

    Returns:
        The API key if valid

    Raises:
        HTTPException: 403 if API key is invalid or missing
    """
    if not api_key:
        raise HTTPException(
            status_code=403,
            detail="Missing API Key. Include X-API-Key header in your request."
        )
    if api_key != API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Invalid API Key"
        )
    return api_key

# Optional dependencies
try:
    from prometheus_client import generate_latest
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    logger.warning("prometheus-client not installed, /metrics endpoint disabled")

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False
    limiter = None
    logger.warning("slowapi not installed, rate limiting disabled")

# Create conditional rate limit decorator
def rate_limit(limit_string: str):
    """Conditional rate limiting decorator"""
    def decorator(func):
        if RATE_LIMITING_AVAILABLE:
            return limiter.limit(limit_string)(func)
        return func
    return decorator

app = FastAPI(
    title="TerraSafe API",
    description="Intelligent Terraform Security Scanner with hybrid 60% rules + 40% ML approach",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add security middleware
allowed_hosts = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts
)

# Add CORS middleware with proper production config
allowed_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # Configure for production
    allow_credentials=False,  # Disable credentials for security
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Add rate limiting if available
if RATE_LIMITING_AVAILABLE:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize scanner components (singleton pattern)
parser = HCLParser()
rule_analyzer = SecurityRuleEngine()
model_manager = ModelManager()
ml_predictor = MLPredictor(model_manager)
scanner = IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint for container orchestration and monitoring

    Returns:
        Dict with status and service information
    """
    return {
        "status": "healthy",
        "service": "TerraSafe",
        "version": "1.0.0",
        "rate_limiting": RATE_LIMITING_AVAILABLE,
        "metrics": METRICS_AVAILABLE
    }


@app.post("/scan", dependencies=[Depends(verify_api_key)])
@rate_limit("10/minute")
async def scan_terraform(
    request: Request,
    file: UploadFile = File(..., description="Terraform configuration file (.tf)")
) -> JSONResponse:
    """
    Scan uploaded Terraform file for security vulnerabilities

    Uses hybrid approach:
    - 60% rule-based analysis (hardcoded secrets, open ports, etc.)
    - 40% ML anomaly detection (IsolationForest)

    Args:
        request: FastAPI request (for rate limiting)
        file: Uploaded .tf file

    Returns:
        JSON with scan results including score, vulnerabilities, and recommendations

    Raises:
        HTTPException: 400 if file format invalid, 422 if scan fails
    """

    # Validate file extension
    if not file.filename.endswith(('.tf', '.tf.json')):
        raise HTTPException(
            status_code=400,
            detail="File must be a Terraform file (.tf or .tf.json)"
        )

    # Validate file size (max 10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE / (1024*1024)}MB"
        )

    # Create temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.tf', mode='wb') as tmp_file:
        tmp_file.write(content)
        tmp_path = tmp_file.name

    try:
        # Run scan in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, scanner.scan, tmp_path)

        if results['score'] == -1:
            raise HTTPException(
                status_code=422,
                detail=results.get('error', 'Terraform scan failed')
            )

        logger.info(f"Scanned file '{file.filename}' - Score: {results['score']}/100")
        return JSONResponse(content=results, status_code=200)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error scanning file: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during scan: {str(e)}"
        )
    finally:
        # Cleanup temp file
        Path(tmp_path).unlink(missing_ok=True)


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    if not METRICS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Metrics not available. Install prometheus-client.")
    return PlainTextResponse(generate_latest())


@app.get("/api/docs")
async def api_documentation() -> Dict[str, Any]:
    """
    Return API usage documentation and examples

    Returns:
        Dict with endpoints description and usage examples
    """
    return {
        "endpoints": {
            "/health": {
                "method": "GET",
                "description": "Health check and service status",
                "example": "curl http://localhost:8000/health"
            },
            "/scan": {
                "method": "POST",
                "description": "Upload and scan Terraform file (requires API key)",
                "authentication": "X-API-Key header required",
                "rate_limit": "10 requests/minute per IP" if RATE_LIMITING_AVAILABLE else "Unlimited",
                "max_file_size": "10MB",
                "example": "curl -X POST -H 'X-API-Key: your-api-key-here' -F 'file=@terraform.tf' http://localhost:8000/scan"
            },
            "/metrics": {
                "method": "GET",
                "description": "Prometheus metrics (if enabled)",
                "example": "curl http://localhost:8000/metrics"
            }
        },
        "response_format": {
            "score": "int (0-100, higher = more risky)",
            "rule_based_score": "int (0-100)",
            "ml_score": "float (0-100)",
            "confidence": "str (LOW/MEDIUM/HIGH)",
            "vulnerabilities": "list of detected issues"
        }
    }


def main():
    """
    Run API server with uvicorn

    Production deployment should use:
    - uvicorn with --workers flag
    - Reverse proxy (nginx/traefik)
    - HTTPS/TLS termination
    """
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )


if __name__ == "__main__":
    main()
