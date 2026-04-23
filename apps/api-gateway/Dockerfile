FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .

RUN pip install poetry && \
    poetry config virtualenvs.in-project true && \
    poetry install --no-dev --no-interaction

FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY app /app/app
COPY . /app/

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app" \
    APP_NAME="api-gateway" \
    ENVIRONMENT="production"

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]