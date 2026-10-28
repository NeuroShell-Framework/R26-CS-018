FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System dependencies (build-essential for native wheels, libgomp1 for torch)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source and required runtime assets
COPY src/ ./src/
COPY knowledge_base/ ./knowledge_base/
COPY data/tool_map.json ./data/tool_map.json

# Environment defaults (override via docker-compose or .env)
ENV OLLAMA_HOST=http://host.docker.internal:11434 \
    OLLAMA_MODEL=neuroshell-c2-gemma2-final \
    REDIS_URL=redis://redis:6379 \
    PORT=8002

EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=10s --retries=5 \
    CMD curl -fsS http://localhost:8002/health || exit 1

CMD ["uvicorn", "src.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8002", \
     "--workers", "1"]
