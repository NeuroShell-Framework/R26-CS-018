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

    # Self-Consistency & Semantic Entropy
    self_consistency_trigger_threshold: float = Field(
        default=0.7,
        description="Tier 1 confidence threshold below which Tier 2 self-consistency triggers"
    )
    self_consistency_samples: int = Field(
        default=5,
        description="Number N of candidate samples to draw in Tier 2"
    )
    self_consistency_temperature: float = Field(
        default=0.7,
        description="Sampling temperature for Tier 2 disagreement resampling"
    )
    entropy_low_threshold: float = Field(
        default=0.3,
        description="Semantic entropy upper bound for low uncertainty band (H < 0.3)"
    )
    entropy_high_threshold: float = Field(
        default=0.8,
        description="Semantic entropy lower bound for high uncertainty band (H > 0.8)"
    )

    # Scope & Safety
    scope_mode: Literal["research", "strict", "production"] = Field(default="research")

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
    cve_grounding_path: str = Field(
        default="data/cve_grounding.json",
        description="Path to offline local CVE grounding reference dataset"
    )
    audit_db_path: str = Field(
        default="data/audit_log.db",
        description="Path to SQLite database for durable audit logging and escalation queue"
    )

    # Cache
    lru_cache_max_size: int = Field(default=256)

    # Downstream planner integration (outbound, non-blocking)
    planner_enabled: bool = Field(
        default=False,
        description="Forward parsed intents to the downstream planner service"
    )
    planner_url: str = Field(default="http://127.0.0.1:8002")

    planner_api_key: str = Field(
        default="neuroshell-c2-secret-key",
        description="x-api-key used to authenticate with the planner service",
    )
    planner_timeout_seconds: int = Field(
        default=300,
        description="Max wait for the planner response (includes LLM inference)",
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
