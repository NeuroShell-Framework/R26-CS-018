# NeuroShell Core - Microservices Monorepo

A production-ready microservices architecture built with Python, FastAPI, Kong API Gateway, and Docker.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Kong API Gateway                                 │
│                       (Port 8000 - HTTP, 8443 - HTTPS)                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          │                           │                           │
          ▼                           ▼                           ▼
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│ adaptive-execution  │    │ ai-vulnerability    │    │ intent-recognition  │
│ -error-recovery     │    │ -analysis          │    │                    │
│ (Port 8001)        │    │ (Port 8002)        │    │ (Port 8004)        │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
                                      │
                                      ▼
                         ┌─────────────────────┐
                         │ dynamic-planner    │
                         │ -rag               │
                         │ (Port 8003)       │
                         └─────────────────────┘
```

## Services

| Service | Port | Endpoint | Description |
|---------|------|----------|-------------|
| Kong Gateway | 8000 | / | API Gateway |
| adaptive-execution-error-recovery | 8001 | /api/v1/process-error | Adaptive error recovery |
| ai-vulnerability-analysis | 8002 | /api/v1/analyze | AI vulnerability scanning |
| dynamic-planner-rag | 8003 | /api/v1/plan | Dynamic planning with RAG |
| intent-recognition | 8004 | /api/v1/recognize | Intent recognition |

## Project Structure

```
neuroshell-core/
├── .github/workflows/       # GitHub Actions CI/CD
├── apps/
│   ├── api-gateway/        # API Gateway service
│   └── services/
│       ├── adaptive-execution-error-recovery/
│       ├── ai-vulnerability-analysis/
│       ├── dynamic-planner-rag/
│       └── intent-recognition/
├── shared/                 # Shared Python package
├── infra/
│   ├── kong/              # Kong gateway config
│   └── docker/             # Docker compose files
├── configs/
│   ├── dev/
│   ├── staging/
│   └── prod/
├── scripts/                # Utility scripts
└── tests/                  # Test suite
```

## Quick Start

### Prerequisites

- Python 3.11+
- Poetry
- Docker & Docker Compose

### Local Development

1. **Install dependencies:**
```bash
poetry install
```

2. **Run individual service:**
```bash
cd apps/services/adaptive-execution-error-recovery
poetry run python main.py
```

3. **Run with Docker Compose (dev):**
```bash
cd infra/docker
docker-compose -f dev-compose.yml up
```

### Running with Kong

Start Kong gateway and all services:
```bash
cd infra/docker
docker-compose -f dev-compose.yml up -d kong
docker-compose -f dev-compose.yml up -d adaptive-execution-error-recovery
docker-compose -f dev-compose.yml up -d ai-vulnerability-analysis
docker-compose -f dev-compose.yml up -d dynamic-planner-rag
docker-compose -f dev-compose.yml up -d intent-recognition
```

### Production Build

```bash
cd infra/docker
docker-compose -f prod-compose.yml build
docker-compose -f prod-compose.yml up -d
```

## API Examples

### Adaptive Error Recovery

```bash
curl -X POST http://localhost:8000/api/adaptive-error-recovery/api/v1/process-error \
  -H "Content-Type: application/json" \
  -d '{
    "error": {
      "error_type": "TimeoutError",
      "message": "Request timed out",
      "severity": "medium",
      "category": "timeout"
    }
  }'
```

### AI Vulnerability Analysis

```bash
curl -X POST http://localhost:8000/api/ai-vulnerability-analysis/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "target": "gpt-model-v1",
    "target_type": "model"
  }'
```

### Dynamic Planner RAG

```bash
curl -X POST http://localhost:8000/api/dynamic-planner-rag/api/v1/plan \
  -H "Content-Type: application/json" \
  -d '{
    "goal": "Recover from API error",
    "context": "Using REST API"
  }'
```

### Intent Recognition

```bash
curl -X POST http://localhost:8000/api/intent-recognition/api/v1/recognize \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Fix the error that occurred"
  }'
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_NAME` | Service name | service-specific |
| `ENVIRONMENT` | Environment | development |
| `DEBUG` | Debug mode | true |
| `LOG_LEVEL` | Logging level | DEBUG |
| `HOST` | Host to bind | 0.0.0.0 |
| `PORT` | Port to bind | 8000 |

## Testing

```bash
poetry run pytest -v
```

## Linting

```bash
poetry run ruff check .
poetry run black --check .
```

## Adding a New Service

1. Create service directory: `apps/services/<service-name>/`
2. Create `pyproject.toml` with service configuration
3. Create `app/` module with `__init__.py`, `config.py`, `models.py`, `router.py`
4. Create `main.py` entry point
5. Create `Dockerfile`
6. Add service to `infra/docker/dev-compose.yml`
7. Add service to `infra/kong/kong.yml` routes

## Troubleshooting

### Port Conflicts

If you get port conflicts, change the port mappings in `docker-compose.dev.yml`:
```yaml
ports:
  - "8005:8000"  # Change 8005 to available port
```

### Container Won't Start

Check logs:
```bash
docker-compose logs <service-name>
```

### Kong Routing Issues

Verify Kong declarative config:
```bash
curl http://localhost:8001/services
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Proprietary - NeuroShell Team