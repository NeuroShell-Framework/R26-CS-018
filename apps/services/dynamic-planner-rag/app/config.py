"""Configuration for Dynamic Planner RAG Service."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings for dynamic planner RAG service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "dynamic-planner-rag"
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

    max_plan_steps: int = 10
    rag_retrieval_limit: int = 5
    enable_reasoning: bool = True


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()