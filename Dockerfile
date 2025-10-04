# Multi-stage build for security and size optimization
FROM python:3.10-slim as builder

# Security: Run as non-root
RUN groupadd -r scanner && useradd -r -g scanner scanner

WORKDIR /build

# Install dependencies in virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.10-slim

# Security hardening
RUN groupadd -r scanner && useradd -r -g scanner scanner \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=scanner:scanner terrasafe/ ./terrasafe/
COPY --chown=scanner:scanner models/ ./models/
COPY --chown=scanner:scanner security_scanner.py .

# Security: Create temp directory
RUN mkdir -p /tmp/terrasafe && chown scanner:scanner /tmp/terrasafe

# Switch to non-root user
USER scanner

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import terrasafe; print('ok')" || exit 1

# Default command
ENTRYPOINT ["python", "security_scanner.py"]

# Labels for metadata
LABEL maintainer="terrasafe@utfpr.edu.br" \
      version="1.0.0" \
      description="Intelligent Terraform Security Scanner" \
      org.opencontainers.image.source="https://github.com/yourusername/terrasafe"
