"""Exception classes for NeuroShell services."""

from typing import Any, Optional


class NeuroShellException(Exception):
    """Base exception for NeuroShell services."""

    def __init__(self, message: str = "An error occurred", code: str = "INTERNAL_ERROR"):
        self.message = message
        self.code = code
        super().__init__(self.message)


class AuthenticationError(NeuroShellException):
    """Authentication related errors."""

    def __init__(self, message: str = "Authentication failed", code: str = "AUTH_ERROR"):
        super().__init__(message, code)


class ValidationError(NeuroShellException):
    """Validation related errors."""

    def __init__(self, message: str = "Validation failed", code: str = "VALIDATION_ERROR"):
        super().__init__(message, code)


class NotFoundError(NeuroShellException):
    """Resource not found errors."""

    def __init__(self, message: str = "Resource not found", code: str = "NOT_FOUND"):
        super().__init__(message, code)


class RateLimitError(NeuroShellException):
    """Rate limit exceeded errors."""

    def __init__(self, message: str = "Rate limit exceeded", code: str = "RATE_LIMIT"):
        super().__init__(message, code)


class ServiceUnavailableError(NeuroShellException):
    """Service unavailable errors."""

    def __init__(self, message: str = "Service unavailable", code: str = "SERVICE_UNAVAILABLE"):
        super().__init__(message, code)