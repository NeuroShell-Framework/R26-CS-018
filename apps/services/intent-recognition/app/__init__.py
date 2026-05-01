"""Intent Recognition Service - Main application."""

import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from app import config, models, router
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from neuroshell_shared.logging import get_logger, setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    setup_logging()
    logger = get_logger(__name__)
    logger.info(f"Starting {config.settings.app_name} v{config.settings.app_version}")
    app.state.start_time = time.time()
    yield
    logger.info(f"Shutting down {config.settings.app_name}")


def create_app() -> FastAPI:
    settings = config.settings
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Intent Recognition Service",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=settings.cors_methods,
        allow_headers=settings.cors_headers,
    )

    app.include_router(router.router, prefix="/api/v1", tags=["intent-recognition"])

    @app.get("/health")
    async def health():
        uptime = time.time() - app.state.start_time
        from neuroshell_shared.models import HealthResponse

        return HealthResponse(
            status="healthy",
            service=settings.app_name,
            version=settings.app_version,
            uptime=uptime,
        )

    return app


app = create_app()
