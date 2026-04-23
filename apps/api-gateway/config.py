"""Configuration for API Gateway Service."""

from functools import lru_cache
from typing import Dict

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings for API gateway service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "api-gateway"
    app_version: str = "0.1.0"
    debug: bool = True
    environment: str = "development"

    host: str = "0.0.0.0"
    port: int = 8000

    cors_origins: list[str] = ["*"]
    cors_methods: list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    cors_headers: list[str] = ["*"]

    log_level: str = "DEBUG"
    log_format: str = "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}"

    upstream_urls: Dict[str, str] = {
        "adaptive_error_recovery": "http://localhost:8001",
        "ai_vulnerability_analysis": "http://localhost:8002",
        "dynamic_planner_rag": "http://localhost:8003",
        "intent_recognition": "http://localhost:8004",
    }

    timeout_seconds: int = 30
    max_retries: int = 3


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()