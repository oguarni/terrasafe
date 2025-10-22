# Multi-stage build for security and size optimization
# Stage 1: Builder
FROM python:3.10-slim as builder

WORKDIR /build

# Install dependencies in virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements first for better caching
COPY requirements.txt .

# Upgrade pip and install dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production runtime
FROM python:3.10-slim

# Security hardening
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        dumb-init \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r scanner --gid=1000 \
    && useradd -r -g scanner --uid=1000 --no-log-init --create-home scanner

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code with proper ownership
COPY --chown=scanner:scanner terrasafe/ ./terrasafe/
COPY --chown=scanner:scanner models/ ./models/

# Create necessary directories
RUN mkdir -p /app/models /tmp/terrasafe && \
    chown -R scanner:scanner /app /tmp/terrasafe

# Security: Allow volumes for runtime data
VOLUME ["/app/models", "/tmp/terrasafe"]

# Switch to non-root user
USER scanner

# Health check with timeout
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys; from terrasafe import __version__; sys.exit(0)" || exit 1

# Default command - use dumb-init for proper signal handling
ENTRYPOINT ["/usr/bin/dumb-init", "--", "python", "-m", "terrasafe.main"]

# OCI-compliant labels for metadata
LABEL maintainer="terrasafe@utfpr.edu.br" \
      version="1.0.0" \
      description="Intelligent Terraform Security Scanner" \
      org.opencontainers.image.title="TerraSafe" \
      org.opencontainers.image.description="Terraform security scanner with 60% rule-based + 40% ML anomaly detection" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.authors="UTFPR Engineering Team" \
      org.opencontainers.image.url="https://github.com/yourusername/terrasafe" \
      org.opencontainers.image.source="https://github.com/yourusername/terrasafe" \
      org.opencontainers.image.vendor="UTFPR" \
      org.opencontainers.image.licenses="MIT"
