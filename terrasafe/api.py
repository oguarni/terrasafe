#!/usr/bin/env python3
"""FastAPI REST API for TerraSafe with rate limiting and async support"""
import tempfile
import asyncio
import hashlib
from pathlib import Path
from typing import Dict, Any
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Security, Depends
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import bcrypt
import aiofiles
import aiofiles.os

from terrasafe.infrastructure.parser import HCLParser
from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.application.scanner import IntelligentSecurityScanner
from terrasafe.config.settings import get_settings
from terrasafe.config.logging import setup_logging, get_logger, set_correlation_id, clear_correlation_id
from terrasafe.infrastructure.database import get_db_manager
from terrasafe.infrastructure.repositories import ScanRepository
from terrasafe.infrastructure.rate_limiter import FallbackRateLimiter
from terrasafe.infrastructure.validation import sanitize_filename

# Get settings
settings = get_settings()

# Configure logging
setup_logging(
    log_level=settings.log_level,
    log_format=settings.log_format,
    log_file=settings.log_file
)
logger = get_logger(__name__)

# API Key Authentication with bcrypt
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def hash_api_key(api_key: str) -> str:
    """
    Hash an API key using bcrypt.

    Args:
        api_key: Plain text API key

    Returns:
        Bcrypt hashed API key
    """
    return bcrypt.hashpw(api_key.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_api_key_hash(api_key: str, hashed_key: str) -> bool:
    """
    Verify an API key against its bcrypt hash.

    Args:
        api_key: Plain text API key to verify
        hashed_key: Bcrypt hash to verify against

    Returns:
        True if key matches, False otherwise
    """
    try:
        return bcrypt.checkpw(api_key.encode('utf-8'), hashed_key.encode('utf-8'))
    except Exception as e:
        logger.error(f"Error verifying API key: {e}")
        return False

async def verify_api_key(api_key: str = Security(api_key_header)):
    """
    Verify API key from request header using bcrypt.

    Args:
        api_key: API key from X-API-Key header

    Returns:
        The API key if valid

    Raises:
        HTTPException: 403 if API key is invalid or missing
    """
    if not api_key:
        logger.warning("API request with missing API key")
        raise HTTPException(
            status_code=403,
            detail="Missing API Key. Include X-API-Key header in your request."
        )

    # Verify against hashed key from settings
    if not verify_api_key_hash(api_key, settings.api_key_hash):
        logger.warning("API request with invalid API key")
        raise HTTPException(
            status_code=403,
            detail="Invalid API Key"
        )

    logger.debug("API key verified successfully")
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

    # Use Redis for distributed rate limiting in production
    try:
        limiter = Limiter(
            key_func=get_remote_address,
            storage_uri=settings.redis_url if not settings.is_development() else None,
            default_limits=[f"{settings.rate_limit_requests}/{settings.rate_limit_window_seconds}seconds"]
        )
        RATE_LIMITING_AVAILABLE = True
        logger.info(f"Rate limiting enabled: {settings.rate_limit_requests} requests per {settings.rate_limit_window_seconds}s")
    except Exception as redis_error:
        # Redis connection failed, use fallback
        logger.warning(f"Redis connection failed: {redis_error}. Using fallback rate limiter.")
        RATE_LIMITING_AVAILABLE = False
        limiter = None
except ImportError:
    RATE_LIMITING_AVAILABLE = False
    limiter = None
    logger.warning("slowapi not installed, using fallback rate limiter")

# Initialize fallback rate limiter (always available)
fallback_limiter = FallbackRateLimiter(
    max_requests=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds
)

# Middleware for fallback rate limiting
async def check_fallback_rate_limit(request: Request):
    """Check rate limit using fallback limiter if needed"""
    if not RATE_LIMITING_AVAILABLE:
        client_ip = request.client.host if request.client else "unknown"
        if not fallback_limiter.check_rate_limit(client_ip):
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {settings.rate_limit_requests} requests per {settings.rate_limit_window_seconds}s"
            )

# Create conditional rate limit decorator
def rate_limit(limit_string: str):
    """Conditional rate limiting decorator"""
    def decorator(func):
        if RATE_LIMITING_AVAILABLE:
            return limiter.limit(limit_string)(func)
        return func
    return decorator

# Initialize scanner components (singleton pattern) - before app initialization
parser = HCLParser()
rule_analyzer = SecurityRuleEngine()
model_manager = ModelManager()
ml_predictor = MLPredictor(model_manager)
scanner = IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)

# Initialize database manager
db_manager = get_db_manager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan event handler for FastAPI application.
    Manages startup and shutdown operations.
    """
    # Startup
    try:
        if settings.database_url:
            await db_manager.connect()
            logger.info("Database connection established")
        else:
            logger.warning("No database URL configured - database features disabled")
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        # Don't fail startup if database is unavailable
        logger.warning("Continuing without database persistence")

    yield  # Application runs here

    # Shutdown
    try:
        await db_manager.disconnect()
        logger.info("Database connection closed")
    except Exception as e:
        logger.error(f"Error closing database connection: {e}")


app = FastAPI(
    title="TerraSafe API",
    description="Intelligent Terraform Security Scanner with hybrid 60% rules + 40% ML approach",
    version="1.0.0",
    docs_url="/docs" if not settings.is_production() else None,
    redoc_url="/redoc" if not settings.is_production() else None,
    debug=settings.debug,
    lifespan=lifespan
)

# Add security middleware - use settings for allowed hosts
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.is_development() else ["localhost", "127.0.0.1"]
)

# Add CORS middleware with proper production config
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api_cors_origins,
    allow_credentials=False,  # Disable credentials for security
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key", "X-Correlation-ID"],
)

# Add rate limiting if available
if RATE_LIMITING_AVAILABLE:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware for correlation IDs
@app.middleware("http")
async def add_correlation_id(request: Request, call_next):
    """Add correlation ID to requests for tracing"""
    # Get correlation ID from header or generate new one
    correlation_id = request.headers.get("X-Correlation-ID")
    cid = set_correlation_id(correlation_id)

    try:
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = cid
        return response
    finally:
        clear_correlation_id()


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint for container orchestration and monitoring

    Returns:
        Dict with status and service information
    """
    # Check database health
    db_healthy = await db_manager.health_check() if db_manager.is_connected else None

    return {
        "status": "healthy",
        "service": "TerraSafe",
        "version": "1.0.0",
        "rate_limiting": {
            "enabled": True,  # Always enabled (fallback or Redis)
            "using_redis": RATE_LIMITING_AVAILABLE,
            "using_fallback": not RATE_LIMITING_AVAILABLE
        },
        "metrics": METRICS_AVAILABLE,
        "database": {
            "connected": db_manager.is_connected,
            "healthy": db_healthy
        }
    }


@app.post("/scan", dependencies=[Depends(verify_api_key), Depends(check_fallback_rate_limit)])
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
    if not file.filename or not file.filename.endswith(('.tf', '.tf.json')):
        logger.warning(f"Invalid file extension: {sanitize_filename(file.filename or '')}")
        raise HTTPException(
            status_code=400,
            detail="File must be a Terraform file (.tf or .tf.json)"
        )

    # Validate file size using settings
    content = await file.read()
    if len(content) > settings.max_file_size_bytes:
        logger.warning(f"File too large: {len(content)} bytes (max: {settings.max_file_size_bytes})")
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {settings.max_file_size_mb}MB"
        )

    # Validate file content is not empty
    if len(content) == 0:
        logger.warning(f"Empty file uploaded: {sanitize_filename(file.filename or '')}")
        raise HTTPException(
            status_code=400,
            detail="File is empty"
        )

    # Create temp file using async operations
    tmp_path = None
    try:
        # Create temp file
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.tf', mode='wb')
        tmp_path = tmp_file.name
        tmp_file.close()

        # Write content asynchronously
        async with aiofiles.open(tmp_path, 'wb') as f:
            await f.write(content)

        # Run scan in thread pool with timeout to avoid blocking event loop
        loop = asyncio.get_running_loop()
        try:
            results = await asyncio.wait_for(
                loop.run_in_executor(None, scanner.scan, tmp_path),
                timeout=settings.scan_timeout_seconds
            )
        except asyncio.TimeoutError:
            logger.error(f"Scan timeout for file '{sanitize_filename(file.filename or '')}' after {settings.scan_timeout_seconds}s")
            raise HTTPException(
                status_code=504,
                detail=f"Scan timeout after {settings.scan_timeout_seconds} seconds"
            )

        if results['score'] == -1:
            logger.error(f"Scan failed for file '{sanitize_filename(file.filename or '')}': {results.get('error')}")
            raise HTTPException(
                status_code=422,
                detail=results.get('error', 'Terraform scan failed')
            )

        logger.info(f"Successfully scanned file '{sanitize_filename(file.filename or '')}' - Score: {results['score']}/100")

        # Save scan results to database if available
        if db_manager.is_connected:
            try:
                async with db_manager.session() as session:
                    scan_repo = ScanRepository(session)

                    # Calculate file hash for database record
                    file_hash = hashlib.sha256(content).hexdigest()

                    # Get correlation ID from context
                    correlation_id_value = request.headers.get("X-Correlation-ID")

                    # Save scan to database
                    await scan_repo.create(
                        filename=file.filename,
                        file_hash=file_hash,
                        file_size_bytes=len(content),
                        score=results['score'],
                        rule_based_score=results['rule_based_score'],
                        ml_score=results['ml_score'],
                        confidence=results['confidence'],
                        scan_duration_seconds=results['performance']['scan_time_seconds'],
                        from_cache=results['performance']['from_cache'],
                        features_analyzed=results['features_analyzed'],
                        vulnerability_summary=results['summary'],
                        vulnerabilities=results['vulnerabilities'],
                        correlation_id=correlation_id_value,
                        environment=settings.environment
                    )
                    logger.debug(f"Scan results saved to database for file '{file.filename}'")
            except Exception as db_error:
                # Log but don't fail the request if database save fails
                logger.error(f"Failed to save scan to database: {db_error}", exc_info=True)

        return JSONResponse(content=results, status_code=200)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error scanning file '{file.filename}': {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Internal server error during scan"
        )
    finally:
        # Cleanup temp file asynchronously
        if tmp_path:
            try:
                await aiofiles.os.remove(tmp_path)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file {tmp_path}: {e}")


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
    logger.info(f"Starting TerraSafe API server on {settings.api_host}:{settings.api_port}")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Debug mode: {settings.debug}")

    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        access_log=True
    )


if __name__ == "__main__":
    main()
