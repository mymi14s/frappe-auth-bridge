"""FastAPI/Starlette middleware for frappe-auth-bridge."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from frappe_auth_bridge.core import FrappeAuthBridge
from frappe_auth_bridge.exceptions import SessionExpiredError


class FrappeAuthMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware for Frappe authentication."""
    
    def __init__(self, app, auth_bridge: FrappeAuthBridge, 
                 session_cookie_name: str = "frappe_session",
                 exempt_paths: list = None):
        """
        Initialize middleware.
        
        Args:
            app: FastAPI/Starlette app
            auth_bridge: FrappeAuthBridge instance
            session_cookie_name: Session cookie name
            exempt_paths: Paths to exempt from authentication
        """
        super().__init__(app)
        self.auth_bridge = auth_bridge
        self.session_cookie_name = session_cookie_name
        self.exempt_paths = exempt_paths or ['/login', '/logout', '/docs', '/openapi.json']
    
    async def dispatch(self, request: Request, call_next):
        """Process request."""
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)
        
        session_token = self._extract_token(request)
        
        if session_token:
            try:
                session = self.auth_bridge.session_store.get(session_token)
                
                if session:
                    if session.needs_refresh:
                        session = self.auth_bridge.refresh_token(session.session_id)
                    
                    request.state.user = session.user
                    request.state.frappe_session = session
                else:
                    request.state.user = None
                    
            except SessionExpiredError:
                request.state.user = None
            except Exception:
                request.state.user = None
        else:
            request.state.user = None
        
        response = await call_next(request)
        return response
    
    def _extract_token(self, request: Request) -> str:
        """Extract authentication token from request."""
        token = request.cookies.get(self.session_cookie_name)
        if token:
            return token
        
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]
        
        return None
