"""NeuroShell Shared Package - Common utilities for all microservices."""

__version__ = "0.1.0"

from neuroshell_shared.config import Settings, get_settings
from neuroshell_shared.logging import setup_logging, get_logger
from neuroshell_shared.models import (
    APIResponse,
    ErrorResponse,
    HealthResponse,
    PaginationParams,
)
from neuroshell_shared.auth import (
    create_access_token,
    decode_token,
    verify_password,
    get_password_hash,
)
from neuroshell_shared.exceptions import (
    NeuroShellException,
    AuthenticationError,
    ValidationError,
    NotFoundError,
)

__all__ = [
    "__version__",
    "Settings",
    "get_settings",
    "setup_logging",
    "get_logger",
    "APIResponse",
    "ErrorResponse",
    "HealthResponse",
    "PaginationParams",
    "create_access_token",
    "decode_token",
    "verify_password",
    "get_password_hash",
    "NeuroShellException",
    "AuthenticationError",
    "ValidationError",
    "NotFoundError",
]