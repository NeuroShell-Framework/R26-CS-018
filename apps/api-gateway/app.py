"""API Gateway Service - Main application."""

import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from neuroshell_shared.logging import setup_logging, get_logger

from app import config


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    setup_logging()
    logger = get_logger(__name__)
    logger.info(f"Starting {config.settings.app_name} v{config.settings.app_version}")
    app.state.start_time = time.time()
    app.state.service_urls = {
        "adaptive-error-recovery": config.settings.upstream_urls.get("adaptive_error_recovery", "http://localhost:8001"),
        "ai-vulnerability-analysis": config.settings.upstream_urls.get("ai_vulnerability_analysis", "http://localhost:8002"),
        "dynamic-planner-rag": config.settings.upstream_urls.get("dynamic_planner_rag", "http://localhost:8003"),
        "intent-recognition": config.settings.upstream_urls.get("intent_recognition", "http://localhost:8004"),
    }
    logger.info(f"Service URLs configured: {app.state.service_urls}")
    yield
    logger.info(f"Shutting down {config.settings.app_name}")


def create_app() -> FastAPI:
    settings = config.settings
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="NeuroShell API Gateway",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=settings.cors_methods,
        allow_headers=settings.cors_headers,
    )

    @app.get("/health")
    async def health(request: Request) -> JSONResponse:
        from neuroshell_shared.models import HealthResponse

        upstream_status = {}
        async with httpx.AsyncClient() as client:
            for service_name, service_url in request.app.state.service_urls.items():
                try:
                    response = await client.get(f"{service_url}/health", timeout=5.0)
                    upstream_status[service_name] = "healthy" if response.status_code == 200 else "unhealthy"
                except Exception:
                    upstream_status[service_name] = "unavailable"

        all_healthy = all(s == "healthy" for s in upstream_status.values())
        status = "healthy" if all_healthy else "degraded"

        uptime = time.time() - request.app.state.start_time
        return JSONResponse(
            status_code=200 if all_healthy else 503,
            content={
                "status": status,
                "service": settings.app_name,
                "version": settings.app_version,
                "uptime": uptime,
                "upstream_services": upstream_status,
            },
        )

    @app.get("/")
    async def root() -> JSONResponse:
        return JSONResponse(
            content={
                "service": settings.app_name,
                "version": settings.app_version,
                "status": "operational",
                "docs": "/docs",
            }
        )

    @app.get("/routes")
    async def routes(request: Request) -> JSONResponse:
        return JSONResponse(
            content={
                "services": list(request.app.state.service_urls.keys()),
                "routes": [
                    "/api/adaptive-error-recovery",
                    "/api/ai-vulnerability-analysis",
                    "/api/dynamic-planner-rag",
                    "/api/intent-recognition",
                ],
            }
        )

    return app


import httpx
from app import routes as gateway_routes

app = create_app()


@gateway_routes.router.get("/proxy/{service}/{path:path}")
async def proxy(service: str, path: str, request: Request):
    """Proxy requests to upstream services."""
    logger = get_logger(__name__)

    service_urls = request.app.state.service_urls.get(service)
    if not service_urls:
        return JSONResponse(
            status_code=404,
            content={"error": f"Service '{service}' not found"},
        )

    upstream_url = f"{service_urls}/{path}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=request.method,
                url=upstream_url,
                headers={k: v for k, v in request.headers.items() if k.lower() not in ["host", "connection"]},
                params=request.query_params,
                timeout=30.0,
            )
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.text else {},
            )
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        return JSONResponse(
            status_code=502,
            content={"error": f"Upstream service error: {str(e)}"},
        )