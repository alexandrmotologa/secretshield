# Build minimal hardened container for SecretShield
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies and uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Install dependencies into virtualenv
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN uv venv /opt/venv && \
    uv pip install --no-cache -e .

# Runtime stage
FROM python:3.12-slim

WORKDIR /app

# Security: Create non-root user
RUN groupadd -g 10001 secretshield && \
    useradd -u 10001 -g secretshield -s /bin/bash -m secretshield

# Copy installed virtualenv
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Ensure data dir exists with proper permissions
RUN mkdir -p /app/data && chown -R secretshield:secretshield /app

USER secretshield:secretshield

EXPOSE 8000

ENV SECRETSHIELD_HOST=0.0.0.0
ENV SECRETSHIELD_PORT=8000
ENV SECRETSHIELD_DATA_DIR=/app/data

VOLUME ["/app/data"]

ENTRYPOINT ["secretshield"]
CMD ["run"]
