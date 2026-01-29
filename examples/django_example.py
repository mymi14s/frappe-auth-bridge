"""Django example settings and views using frappe-auth-bridge."""

# NOTE: This is a simplified example showing how to integrate frappe-auth-bridge
# with Django. In a real Django project, you would split this into proper
# settings.py, views.py, and urls.py files.

# ============================================================================
# DJANGO SETTINGS CONFIGURATION
# ============================================================================

"""
# Add to settings.py:

import os
from frappe_auth_bridge import FrappeAuthBridge

# Frappe Auth Bridge Configuration
FRAPPE_URL = os.getenv("FRAPPE_URL", "https://example.erpnext.com")

FRAPPE_AUTH_BRIDGE = FrappeAuthBridge(
    frappe_url=FRAPPE_URL,
    enable_rate_limiting=True,
    enable_audit_logging=True,
    session_ttl_seconds=3600,
)

# Add middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Add Frappe Auth Middleware
    'frappe_auth_bridge.middleware.django.FrappeAuthMiddleware',
]

# Session configuration
SESSION_COOKIE_NAME = 'frappe_session'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # In production with HTTPS
SESSION_COOKIE_SAMESITE = 'Strict'
"""

# ============================================================================
# DJANGO VIEWS
# ============================================================================

"""
# views.py

import os
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import json


@csrf_exempt
def login_view(request):
    '''Login endpoint - authenticate with username and password.'''
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return JsonResponse({'error': 'Username and password required'}, status=400)
        
        # Authenticate with Frappe
        auth_bridge = settings.FRAPPE_AUTH_BRIDGE
        session = auth_bridge.login_with_password(username, password)
        
        # Create response
        response = JsonResponse({
            'session_id': session.session_id,
            'token': session.token,
            'user_email': session.user.email,
            'roles': session.user.roles,
        })
        
        # Set session cookie
        response.set_cookie(
            'frappe_session',
            session.session_id,
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=3600,
        )
        
        return response
        
    except Exception as e:
        return JsonResponse({'error': f'Authentication failed: {str(e)}'}, status=401)


@csrf_exempt
def logout_view(request):
    '''Logout endpoint - invalidate session.'''
    session_id = request.COOKIES.get('frappe_session')
    
    if session_id:
        try:
            auth_bridge = settings.FRAPPE_AUTH_BRIDGE
            auth_bridge.logout(session_id)
        except Exception:
            pass
    
    response = JsonResponse({'message': 'Logged out successfully'})
    response.delete_cookie('frappe_session')
    
    return response


def current_user_view(request):
    '''Get current authenticated user.'''
    if not hasattr(request, 'user') or request.user is None:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    user = request.user
    return JsonResponse({
        'email': user.email,
        'name': user.name,
        'full_name': user.full_name,
        'roles': user.roles,
    })


def secure_view(request):
    '''Protected view using middleware authentication.'''
    if not hasattr(request, 'user') or request.user is None:
        return JsonResponse({'error': 'Authentication required'}, status=401)
    
    user = request.user
    return JsonResponse({
        'message': f'Hello, {user.full_name or user.email}!',
        'roles': user.roles,
        'access_level': 'secure',
    })


def admin_only_view(request):
    '''Admin-only view with role checking.'''
    if not hasattr(request, 'user') or request.user is None:
        return JsonResponse({'error': 'Authentication required'}, status=401)
    
    user = request.user
    
    # Check if user has admin role
    if 'Administrator' not in user.roles and 'System Manager' not in user.roles:
        return JsonResponse({'error': 'Admin access required'}, status=403)
    
    return JsonResponse({
        'message': 'Welcome, administrator!',
        'user': user.email,
        'roles': user.roles,
    })
"""

# ============================================================================
# DJANGO URLS
# ============================================================================

"""
# urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('me/', views.current_user_view, name='current_user'),
    path('secure/', views.secure_view, name='secure'),
    path('admin-only/', views.admin_only_view, name='admin_only'),
]
"""

# ============================================================================
# USAGE INSTRUCTIONS
# ============================================================================

"""
To use this example in your Django project:

1. Install frappe-auth-bridge:
   pip install frappe-auth-bridge[django]

2. Configure settings.py as shown above

3. Create views.py with the view functions

4. Add URL patterns to urls.py

5. Run migrations (if needed):
   python manage.py migrate

6. Start the development server:
   python manage.py runserver

7. Test authentication:
   curl -X POST http://localhost:8000/login/ \\
     -H "Content-Type: application/json" \\
     -d '{"username": "user@example.com", "password": "password"}'
"""
