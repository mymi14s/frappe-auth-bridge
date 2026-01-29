"""Authentication decorators for frappe-auth-bridge."""

import functools
from typing import Callable, Optional, Any
from frappe_auth_bridge.core import FrappeAuthBridge
from frappe_auth_bridge.exceptions import AuthenticationError, SessionExpiredError


def frappe_auth_required(
    auth_bridge: Optional[FrappeAuthBridge] = None,
    session_cookie_name: str = "frappe_session",
    header_name: str = "Authorization",
):
    """
    Decorator to require Frappe authentication.
    
    Works with Django, Flask, FastAPI, and vanilla Python functions.
    
    Args:
        auth_bridge: FrappeAuthBridge instance (can be set globally)
        session_cookie_name: Name of session cookie
        header_name: Name of authorization header
        
    Usage:
        @frappe_auth_required
        async def my_view(request):
            # request.user will be available
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            request = _extract_request(args, kwargs)
            
            if request is None:
                raise AuthenticationError("Could not extract request from arguments")
            
            bridge = auth_bridge or _get_global_auth_bridge(request)
            if not bridge:
                raise RuntimeError("FrappeAuthBridge instance not configured")
            
            session_token = _extract_token(request, session_cookie_name, header_name)
            if not session_token:
                raise AuthenticationError("No authentication token provided")
            
            try:
                session = bridge.session_store.get(session_token)
                if not session:
                    raise AuthenticationError("Invalid session")
                
                if session.needs_refresh:
                    session = bridge.refresh_token(session.session_id)
                
                _inject_user(request, session.user)
                
            except SessionExpiredError:
                raise AuthenticationError("Session expired")
            
            return await func(*args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            request = _extract_request(args, kwargs)
            
            if request is None:
                return _vanilla_python_auth(func, auth_bridge, *args, **kwargs)
            
            bridge = auth_bridge or _get_global_auth_bridge(request)
            if not bridge:
                raise RuntimeError("FrappeAuthBridge instance not configured")
            
            session_token = _extract_token(request, session_cookie_name, header_name)
            if not session_token:
                raise AuthenticationError("No authentication token provided")
            
            try:
                session = bridge.session_store.get(session_token)
                if not session:
                    raise AuthenticationError("Invalid session")
                
                if session.needs_refresh:
                    session = bridge.refresh_token(session.session_id)
                
                _inject_user(request, session.user)
                
            except SessionExpiredError:
                raise AuthenticationError("Session expired")
            
            return func(*args, **kwargs)
        
        if functools.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def _extract_request(args: tuple, kwargs: dict) -> Optional[Any]:
    """Extract request object from function arguments."""
    if 'request' in kwargs:
        return kwargs['request']
    
    for arg in args:
        if hasattr(arg, 'META') and hasattr(arg, 'COOKIES'):
            return arg
        if hasattr(arg, '__class__') and 'Request' in arg.__class__.__name__:
            return arg
        if hasattr(arg, 'state') and hasattr(arg, 'cookies'):
            return arg
    
    return None


def _extract_token(
    request: Any, cookie_name: str, header_name: str
) -> Optional[str]:
    """Extract authentication token from request."""
    if hasattr(request, 'COOKIES'):  # Django
        token = request.COOKIES.get(cookie_name)
        if token:
            return token
    elif hasattr(request, 'cookies'):  # Flask/FastAPI
        token = request.cookies.get(cookie_name)
        if token:
            return token
    
    if hasattr(request, 'META'):  # Django
        auth_header = request.META.get(f'HTTP_{header_name.upper()}')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]
    elif hasattr(request, 'headers'):  # Flask/FastAPI
        auth_header = request.headers.get(header_name)
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]
    
    return None


def _inject_user(request: Any, user: Any) -> None:
    """Inject user object into request."""
    # Django
    if hasattr(request, 'META'):
        request.user = user
    # FastAPI
    elif hasattr(request, 'state'):
        request.state.user = user
    # Flask - use g object
    else:
        try:
            from flask import g
            g.user = user
        except ImportError:
            # Fallback: attach to request
            request.user = user


def _get_global_auth_bridge(request: Any) -> Optional[FrappeAuthBridge]:
    """Get global auth bridge from request context."""
    # Django
    if hasattr(request, 'META'):
        return getattr(request, '_frappe_auth_bridge', None)
    # FastAPI
    elif hasattr(request, 'app'):
        return getattr(request.app.state, 'frappe_auth_bridge', None)
    # Flask
    else:
        try:
            from flask import current_app
            return getattr(current_app, 'frappe_auth_bridge', None)
        except ImportError:
            pass
    
    return None


def _vanilla_python_auth(
    func: Callable, bridge: Optional[FrappeAuthBridge], *args, **kwargs
) -> Any:
    """Handle vanilla Python function authentication."""
    if not bridge:
        raise RuntimeError("FrappeAuthBridge instance required for vanilla Python")
    
    session_id = kwargs.pop('session_id', None)
    if not session_id:
        raise AuthenticationError("session_id required for authentication")
    
    try:
        session = bridge.session_store.get(session_id)
        if not session:
            raise AuthenticationError("Invalid session")
        
        if session.needs_refresh:
            session = bridge.refresh_token(session.session_id)
        
        kwargs['user'] = session.user
        
    except SessionExpiredError:
        raise AuthenticationError("Session expired")
    
    return func(*args, **kwargs)
