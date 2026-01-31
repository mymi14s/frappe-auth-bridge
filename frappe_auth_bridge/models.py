"""Data models for frappe-auth-bridge."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class Permission(BaseModel):
    """Represents a user permission."""

    doctype: str
    read: bool = False
    write: bool = False
    create: bool = False
    delete: bool = False
    submit: bool = False
    cancel: bool = False
    amend: bool = False

    class Config:
        frozen = True


class User(BaseModel):
    """Represents an authenticated Frappe user."""

    email: str
    name: str
    full_name: Optional[str] = None
    user_image: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    permissions: List[Permission] = Field(default_factory=list)
    user_type: Optional[str] = None
    language: Optional[str] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Validate email format."""
        if "@" not in v:
            raise ValueError("Invalid email format")
        return v.lower()


class Session(BaseModel):
    """Represents an authenticated session."""

    session_id: str
    token: str
    user: User
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    last_refreshed_at: Optional[datetime] = None
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.utcnow() >= self.expires_at

    @property
    def needs_refresh(self) -> bool:
        """Check if session needs refresh (within 5 minutes of expiry)."""
        from datetime import timedelta

        refresh_threshold = self.expires_at - timedelta(minutes=5)
        return datetime.utcnow() >= refresh_threshold

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class TenantConfig(BaseModel):
    """Configuration for a multi-tenant setup."""

    tenant_id: str
    frappe_url: str
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        frozen = True
