# Frappe Auth Bridge

A secure Python authentication bridge that integrates with [frappe-client](https://github.com/frappe/frappe-client) to authenticate users, persist web sessions, sync roles & permissions, and enable SSO across Django, Flask, FastAPI, and vanilla Python applications.

## Features

- **Secure Authentication** via frappe-client using username/password or API keys
- **Session Management** with encrypted storage and auto-refresh
- **Role & Permission Caching** for fast authorization checks
- **Framework Support** for Django, Flask, FastAPI, and vanilla Python
- **Auto Token Refresh** before expiration
- **Multi-Tenant Support** for multiple Frappe servers
- **Async HTTP** with httpx for high performance
- **Audit Logging** for all authentication events
- **Rate Limiting** to prevent abuse
- **Security First** with Fernet encryption and HTTPS-only cookies

## Installation

### Basic Installation

```bash
pip install frappe-auth-bridge
```

### With Framework Support

```bash
# For Django
pip install frappe-auth-bridge[django]

# For Flask
pip install frappe-auth-bridge[flask]

# For FastAPI
pip install frappe-auth-bridge[fastapi]

# For Redis session backend
pip install frappe-auth-bridge[redis]

# Install all extras
pip install frappe-auth-bridge[all]
```

### Development Installation

```bash
git clone https://github.com/mymi14s/frappe-auth-bridge.git
cd frappe-auth-bridge
pip install -e .
```

## Quick Start

### Vanilla Python

```python
from frappe_auth_bridge import FrappeAuthBridge

# Initialize
auth = FrappeAuthBridge("https://your-frappe-site.com")

# Login
session = auth.login_with_password("user@example.com", "password")
print(f"Logged in as: {session.user.email}")
print(f"Roles: {session.user.roles}")

# Logout
auth.logout(session.session_id)
```

### Using FrappeClient Directly

After authentication, you can access the underlying FrappeClient to perform any Frappe API operations:

```python
from frappe_auth_bridge import FrappeAuthBridge

auth = FrappeAuthBridge("https://your-frappe-site.com")

# Option 1: After login, use auth.client directly
session = auth.login_with_password("user@example.com", "password")

# Now you can use all FrappeClient methods
users = auth.client.get_list("User", fields=["name", "email"])
user_doc = auth.client.get_doc("User", "user@example.com")

# Insert a document
new_todo = auth.client.insert({
    "doctype": "ToDo",
    "description": "My new todo"
})

# Update a document
auth.client.update({
    "doctype": "ToDo",
    "name": new_todo.get("name"),
    "status": "Closed"
})

# Delete a document
auth.client.delete("ToDo", new_todo.get("name"))

# Make API calls
result = auth.client.get_api("frappe.client.get_list", {
    "doctype": "Company",
    "fields": '["name"]'
})

# Option 2: Set credentials for client separately
auth.set_client_credentials("user@example.com", "password")
companies = auth.client.get_list("Company")  # Auto-authenticates

# Option 3: Get a one-off client with explicit credentials
client = auth.get_client(username="user@example.com", password="password")
docs = client.get_list("Customer")

# Option 4: Use API key for client
auth.set_client_api_key("api-key", "api-secret")
items = auth.client.get_list("Item")
```

### FastAPI

```python
from fastapi import FastAPI, Request
from frappe_auth_bridge import FrappeAuthBridge
from frappe_auth_bridge.middleware.fastapi import FrappeAuthMiddleware

app = FastAPI()
auth_bridge = FrappeAuthBridge("https://your-frappe-site.com")

# Add middleware
app.add_middleware(
    FrappeAuthMiddleware,
    auth_bridge=auth_bridge,
    exempt_paths=["/", "/login", "/docs"]
)

@app.get("/secure")
async def secure_endpoint(request: Request):
    if not hasattr(request.state, 'user') or request.state.user is None:
        return {"error": "Not authenticated"}, 401
    
    return {"user": request.state.user.email}
```

### Flask

```python
from flask import Flask, g
from frappe_auth_bridge import FrappeAuthBridge
from frappe_auth_bridge.middleware.flask import FrappeAuthMiddleware, auth_required

app = Flask(__name__)
auth_bridge = FrappeAuthBridge("https://your-frappe-site.com")

# Initialize middleware
FrappeAuthMiddleware(app, auth_bridge)

@app.route("/secure")
@auth_required
def secure():
    return {"user": g.user.email}
```

### Django

```python
# settings.py
from frappe_auth_bridge import FrappeAuthBridge

FRAPPE_AUTH_BRIDGE = FrappeAuthBridge("https://your-frappe-site.com")

MIDDLEWARE = [
    # ... other middleware
    'frappe_auth_bridge.middleware.django.FrappeAuthMiddleware',
]

# views.py
def secure_view(request):
    if not hasattr(request, 'user') or request.user is None:
        return JsonResponse({"error": "Not authenticated"}, status=401)
    
    return JsonResponse({"user": request.user.email})
```

## Configuration

### Environment Variables

```bash
# Optional: Custom encryption key for session storage
export FRAPPE_AUTH_SECRET_KEY="your-secret-key"

# Frappe server URL
export FRAPPE_URL="https://your-frappe-site.com"
```

### Advanced Configuration

```python
from frappe_auth_bridge import FrappeAuthBridge
from frappe_auth_bridge.session import RedisSessionStore
from frappe_auth_bridge.security import EncryptionManager

# Custom encryption
encryption = EncryptionManager("custom-key")

# Redis session backend
session_store = RedisSessionStore(
    encryption_manager=encryption,
    redis_url="redis://localhost:6379"
)

# Initialize with custom settings
auth = FrappeAuthBridge(
    frappe_url="https://your-frappe-site.com",
    session_store=session_store,
    enable_rate_limiting=True,
    enable_audit_logging=True,
    session_ttl_seconds=3600,  # 1 hour
)
```

## Multi-Tenant Support

from frappe_auth_bridge import FrappeAuthBridge
from frappe_auth_bridge.models import TenantConfig

auth = FrappeAuthBridge(
    frappe_url="https://your-frappe-site.com",
    multi_tenant=True
)

# Add tenants
auth.add_tenant(TenantConfig(
    tenant_id="company_a",
    frappe_url="https://company-a.your-frappe-site.com"
))

auth.add_tenant(TenantConfig(
    tenant_id="company_b",
    frappe_url="https://company-b.your-frappe-site.com"
))

# Login to specific tenant
session = auth.login_with_password(
    "user@example.com",
    "password",
    tenant_id="company_a"
)
```

## API Reference

### FrappeAuthBridge

Main authentication class:

- `login_with_password(username, password, tenant_id=None)` - Authenticate with credentials
- `authenticate_api_key(api_key, api_secret, tenant_id=None)` - Authenticate with API keys
- `refresh_token(session_id)` - Refresh an expiring session
- `logout(session_id)` - Invalidate a session
- `get_user_roles(user_email)` - Get cached user roles
- `get_user_permissions(user_email)` - Get cached permissions
- `validate_permission(user_email, doctype, permission_type)` - Check permission

## Security Features

- **Fernet Encryption** for all session data at rest
- **No Plaintext Passwords** ever stored
- **HTTPS-only Cookies** in production
- **Rate Limiting** with token bucket algorithm
- **Audit Logging** with sensitive field redaction
- **Environment Variable Secrets** only
- **SSL Certificate Verification** enforced
- **Session Auto-Refresh** before expiry
- **Token Revocation** on logout

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=frappe_auth_bridge --cov-report=html

# Run specific test
pytest tests/test_core.py -v
```

## Examples

See the `examples/` directory for complete working examples:

- `fastapi_example.py` - FastAPI application with login/logout
- `flask_example.py` - Flask application with middleware
- `django_example.py` - Django configuration and views
- `vanilla_example.py` - Standalone Python script

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Credits

Built with:
- [frappe-client](https://github.com/frappe/frappe-client) - Official Frappe Python client
- [cryptography](https://cryptography.io/) - Encryption library
- [httpx](https://www.python-httpx.org/) - Async HTTP client
- [pydantic](https://pydantic.dev/) - Data validation
- [cachetools](https://github.com/tkem/cachetools) - Caching utilities

## Support

For issues and questions:
- GitHub Issues: https://github.com/mymi14s/frappe-auth-bridge/issues
- Documentation: https://mymi14s.github.io/frappe-auth-bridge
