#!/usr/bin/env python3
"""FastAPI REST API for TerraSafe"""
import tempfile
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from terrasafe.infrastructure.parser import HCLParser
from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.application.scanner import IntelligentSecurityScanner

try:
    from prometheus_client import generate_latest
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

app = FastAPI(
    title="TerraSafe API",
    description="Intelligent Terraform Security Scanner",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize scanner components (singleton pattern)
parser = HCLParser()
rule_analyzer = SecurityRuleEngine()
model_manager = ModelManager()
ml_predictor = MLPredictor(model_manager)
scanner = IntelligentSecurityScanner(parser, rule_analyzer, ml_predictor)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "TerraSafe"}


@app.post("/scan")
async def scan_terraform(file: UploadFile = File(...)):
    """Scan uploaded Terraform file"""
    if not file.filename.endswith('.tf'):
        raise HTTPException(status_code=400, detail="File must be a .tf Terraform file")

    # Create temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.tf') as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        tmp_path = tmp_file.name

    try:
        # Scan the file
        results = scanner.scan(tmp_path)

        if results['score'] == -1:
            raise HTTPException(status_code=422, detail=results.get('error', 'Scan failed'))

        return JSONResponse(content=results)
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
async def api_documentation():
    """Return API usage documentation"""
    return {
        "endpoints": {
            "/health": "GET - Health check",
            "/scan": "POST - Upload and scan .tf file",
            "/metrics": "GET - Prometheus metrics"
        },
        "example": "curl -X POST -F 'file=@terraform.tf' http://localhost:8000/scan"
    }


def main():
    """Run API server"""
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
