# VERITAS-Vault Container Image for Google Cloud Run
# Python 3.12 Debian Slim Base
FROM python:3.12-slim-bookworm

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    ENV=production

# Install minimal OS dependencies for headless graphics and certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Set up non-root system user for security
RUN groupadd -g 10001 vaultgroup && \
    useradd -u 10001 -g vaultgroup -s /bin/bash -m vaultuser

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code and assets
COPY . .

# Run static shell build and ensure directory permissions
RUN python scripts/build_shell.py && \
    mkdir -p data/keys data/encrypted_evidence models/known_faces && \
    chown -R vaultuser:vaultgroup /app

# Switch to non-root user
USER vaultuser

# Expose standard Cloud Run port
EXPOSE 8080

# Execute FastAPI via Uvicorn listening on 0.0.0.0 with dynamic Cloud Run $PORT
CMD ["sh", "-c", "exec uvicorn src.pwa.api:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1"]
