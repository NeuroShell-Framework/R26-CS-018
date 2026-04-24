# NeuroShell IRE — Application Settings
# Single source of truth for all configuration values.
# Loaded from environment variables via .env file with sensible defaults
# so the application starts without a .env file present.

from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # API
    ire_api_key: str = Field(default="dev_insecure_key")
    port: int = Field(default=8001)

    # Ollama / Inference
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="gemma4:e4b")
    ollama_timeout_seconds: int = Field(default=60)
    inference_temperature: float = Field(default=0.1)
    inference_max_tokens: int = Field(default=2048)

    # Scope & Safety
    scope_mode: Literal["research", "production"] = Field(default="research")

    # Engagement scope — network architecture validation
    engagement_scope: str = Field(
        default="192.168.0.0/16",
        description="Authorised target network in CIDR notation. "
                    "All targets must fall within this range."
    )
    engagement_name: str = Field(
        default="Lab Environment",
        description="Human-readable name for the engagement scope"
    )
    engagement_mode: Literal["strict", "warn", "disabled"] = Field(
        default="warn",
        description=(
            "strict   = reject out-of-scope targets\n"
            "warn     = allow but add scope warning\n"
            "disabled = skip network architecture validation"
        )
    )
    max_cidr_prefix: int = Field(
        default=30,
        description="Widest allowed scan prefix (e.g. 16 means /16 "
                    "is the largest scan allowed). Prevents /8 scans."
    )
    min_cidr_prefix: int = Field(
        default=32,
        description="Narrowest allowed subnet prefix for subnet targets"
    )

    # Logging
    log_level: str = Field(default="INFO")

    # Feature Flags
    features_config_path: str = Field(
        default="config/features.yaml",
        description="Path to feature flags YAML configuration"
    )

    # Cache
    lru_cache_max_size: int = Field(default=256)


@lru_cache()
def get_settings() -> Settings:
    return Settings()
