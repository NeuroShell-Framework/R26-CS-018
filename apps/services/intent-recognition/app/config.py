"""Configuration for Intent Recognition Service."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings for intent recognition service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "intent-recognition"
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

    intent_confidence_threshold: float = 0.7
    supported_intents: str = "error_recovery,vulnerability_scan,planning,analysis,query"
    enable_fuzzy_matching: bool = True

    use_ml_by_default: bool = True
    model_path: str = "models/intent_model.joblib"
    default_test_size: float = 0.2


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
