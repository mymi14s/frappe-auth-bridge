"""Flask middleware for frappe-auth-bridge."""

from functools import wraps

from flask import current_app, g, request

from frappe_auth_bridge.core import FrappeAuthBridge
from frappe_auth_bridge.exceptions import SessionExpiredError


class FrappeAuthMiddleware:
    """Flask middleware for Frappe authentication."""

    def __init__(
        self,
        app=None,
        auth_bridge: FrappeAuthBridge = None,
        session_cookie_name: str = "frappe_session",
        exempt_paths: list = None,
    ):
        """
        Initialize middleware.

        Args:
            app: Flask app
            auth_bridge: FrappeAuthBridge instance
            session_cookie_name: Session cookie name
            exempt_paths: Paths to exempt from authentication
        """
        self.auth_bridge = auth_bridge
        self.session_cookie_name = session_cookie_name
        self.exempt_paths = exempt_paths or ["/login", "/logout", "/health"]

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app."""
        app.before_request(self.before_request)

        if self.auth_bridge:
            app.frappe_auth_bridge = self.auth_bridge

    def before_request(self):
        """Process request before handling."""
        # Use exact match for '/' to prevent matching everything
        # Use startswith for other paths to allow sub-paths (like /static/)
        for path in self.exempt_paths:
            if path == "/" and request.path == "/":
                return
            if path != "/" and request.path.startswith(path):
                return

        auth_bridge = self.auth_bridge or getattr(current_app, "frappe_auth_bridge", None)
        if not auth_bridge:
            return

        session_token = self._extract_token()

        if session_token:
            try:
                session = auth_bridge.session_store.get(session_token)

                if session:
                    if session.needs_refresh:
                        session = auth_bridge.refresh_token(session.session_id)

                    g.user = session.user
                    g.frappe_session = session
                else:
                    g.user = None

            except SessionExpiredError:
                g.user = None
            except Exception:
                g.user = None
        else:
            g.user = None

    def _extract_token(self) -> str:
        """Extract authentication token from request."""
        token = request.cookies.get(self.session_cookie_name)
        if token:
            return token

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header[7:]

        return None


def auth_required(f):
    """Flask decorator for requiring authentication."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, "user") or g.user is None:
            from flask import jsonify

            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)

    return decorated_function
