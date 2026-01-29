"""Custom exceptions for frappe-auth-bridge."""


class FrappeAuthException(Exception):
    """Base exception for all frappe-auth-bridge errors."""
    pass


class AuthenticationError(FrappeAuthException):
    """Raised when authentication fails."""
    pass


class SessionExpiredError(FrappeAuthException):
    """Raised when a session has expired."""
    pass


class PermissionDeniedError(FrappeAuthException):
    """Raised when user lacks required permissions."""
    pass


class RateLimitExceededError(FrappeAuthException):
    """Raised when rate limit is exceeded."""
    pass


class InvalidTokenError(FrappeAuthException):
    """Raised when a token is invalid or malformed."""
    pass


class TenantNotFoundError(FrappeAuthException):
    """Raised when a tenant configuration is not found."""
    pass
