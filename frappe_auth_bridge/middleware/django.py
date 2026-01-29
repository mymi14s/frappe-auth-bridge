"""Django middleware for frappe-auth-bridge."""

from typing import Callable
from django.http import HttpRequest, HttpResponse, JsonResponse
from frappe_auth_bridge.core import FrappeAuthBridge
from frappe_auth_bridge.exceptions import AuthenticationError, SessionExpiredError


class FrappeAuthMiddleware:
    """Django middleware for Frappe authentication."""
    
    def __init__(self, get_response: Callable):
        """
        Initialize middleware.
        
        Args:
            get_response: Django response callable
        """
        self.get_response = get_response
        self.auth_bridge: FrappeAuthBridge = None
        self.session_cookie_name = "frappe_session"
        self.exempt_paths = ['/login', '/logout', '/health']
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process request."""
        if any(request.path.startswith(path) for path in self.exempt_paths):
            return self.get_response(request)
        
        if not self.auth_bridge:
            from django.conf import settings
            self.auth_bridge = getattr(settings, 'FRAPPE_AUTH_BRIDGE', None)
            if not self.auth_bridge:
                return JsonResponse(
                    {"error": "FRAPPE_AUTH_BRIDGE not configured in settings"},
                    status=500
                )
        
        session_token = self._extract_token(request)
        
        if session_token:
            try:
                session = self.auth_bridge.session_store.get(session_token)
                
                if session:
                    if session.needs_refresh:
                        session = self.auth_bridge.refresh_token(session.session_id)
                    
                    request.user = session.user
                    request.frappe_session = session
                else:
                    request.user = None
                    
            except SessionExpiredError:
                request.user = None
            except Exception as e:
                request.user = None
        else:
            request.user = None
        
        response = self.get_response(request)
        return response
    
    def _extract_token(self, request: HttpRequest) -> str:
        """Extract authentication token from request."""
        token = request.COOKIES.get(self.session_cookie_name)
        if token:
            return token
        
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]
        
        return None
    
    def configure(self, auth_bridge: FrappeAuthBridge, 
                 session_cookie_name: str = "frappe_session",
                 exempt_paths: list = None):
        """
        Configure middleware.
        
        Args:
            auth_bridge: FrappeAuthBridge instance
            session_cookie_name: Session cookie name
            exempt_paths: Paths to exempt from authentication
        """
        self.auth_bridge = auth_bridge
        self.session_cookie_name = session_cookie_name
        if exempt_paths:
            self.exempt_paths = exempt_paths
