FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m spacy download en_core_web_sm

# Copy application source
COPY src/ ./src/
COPY config/ ./config/
COPY data/alias_map.json ./data/alias_map.json

# Environment defaults (override via docker-compose or .env)
ENV OLLAMA_BASE_URL=http://ollama:11434
ENV OLLAMA_MODEL=gemma4:e4b
ENV SCOPE_MODE=research
ENV LOG_LEVEL=INFO
ENV PORT=8001
ENV IRE_API_KEY=changeme

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["uvicorn", "src.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8001", \
     "--workers", "1"]
