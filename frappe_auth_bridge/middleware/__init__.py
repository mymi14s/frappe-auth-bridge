"""Middleware module initialization."""

__all__ = []

# Import middleware classes based on available frameworks
try:
    from frappe_auth_bridge.middleware.django import \
        FrappeAuthMiddleware as DjangoFrappeAuthMiddleware

    __all__.append("DjangoFrappeAuthMiddleware")
except ImportError:
    pass

try:
    from frappe_auth_bridge.middleware.fastapi import \
        FrappeAuthMiddleware as FastAPIFrappeAuthMiddleware

    __all__.append("FastAPIFrappeAuthMiddleware")
except ImportError:
    pass

try:
    from frappe_auth_bridge.middleware.flask import \
        FrappeAuthMiddleware as FlaskFrappeAuthMiddleware

    __all__.append("FlaskFrappeAuthMiddleware")
except ImportError:
    pass
