FROM python:3.10-slim

WORKDIR /app

# System dependencies first (changes rarely, better layer caching)
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Python dependencies (cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code + database migrations (alembic/ and alembic.ini are needed
# so the entrypoint can run `alembic upgrade head` on startup)
COPY terravault/ ./terravault/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY entrypoint.sh ./
RUN mkdir -p models && chmod +x entrypoint.sh

# Security: run as non-root user
RUN useradd -r -s /bin/false appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Entrypoint applies migrations, then runs the CMD (the API server).
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "-m", "terravault.api"]

