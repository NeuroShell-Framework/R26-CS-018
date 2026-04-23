"""Common response models for NeuroShell services."""

from typing import Any, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field


T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """Standard API response wrapper."""

    success: bool = True
    data: Optional[T] = None
    message: Optional[str] = None
    meta: Optional[dict[str, Any]] = None

    class Config:
        arbitrary_types_allowed = True


class ErrorResponse(BaseModel):
    """Error response model."""

    success: bool = False
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None

    class Config:
        json_schema_extra = {"example": {"success": False, "error": "Validation Error", "detail": "Invalid input"}}


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    service: str
    version: str
    uptime: float = Field(..., description="Service uptime in seconds")


class PaginationParams(BaseModel):
    """Pagination parameters."""

    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")
    total: Optional[int] = None
    total_pages: Optional[int] = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""

    success: bool = True
    data: List[T]
    pagination: PaginationParams


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    """User response model."""

    id: str
    email: str
    name: Optional[str] = None
    is_active: bool = True


class LoginRequest(BaseModel):
    """Login request model."""

    email: str
    password: str


class TokenPayload(BaseModel):
    """JWT token payload."""

    sub: str
    exp: int
    iat: int