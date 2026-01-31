"""Frappe Auth Bridge - Secure authentication bridge for Frappe applications."""

from frappe_auth_bridge.core import FrappeAuthBridge
from frappe_auth_bridge.exceptions import (AuthenticationError,
                                           FrappeAuthException,
                                           PermissionDeniedError,
                                           RateLimitExceededError,
                                           SessionExpiredError)
from frappe_auth_bridge.models import Permission, Session, User

__version__ = "0.2.0"
__all__ = [
    "FrappeAuthBridge",
    "FrappeAuthException",
    "AuthenticationError",
    "SessionExpiredError",
    "PermissionDeniedError",
    "RateLimitExceededError",
    "User",
    "Session",
    "Permission",
]
