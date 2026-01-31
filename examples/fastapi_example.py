"""FastAPI example application using frappe-auth-bridge."""

import os

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

from frappe_auth_bridge import FrappeAuthBridge
from frappe_auth_bridge.decorators import frappe_auth_required
from frappe_auth_bridge.middleware.fastapi import FrappeAuthMiddleware

# Initialize FastAPI app
app = FastAPI(title="Frappe Auth Bridge - FastAPI Example")

# Initialize Frappe Auth Bridge
FRAPPE_URL = os.getenv("FRAPPE_URL", "https://example.erpnext.com")
auth_bridge = FrappeAuthBridge(
    frappe_url=FRAPPE_URL,
    enable_rate_limiting=True,
    enable_audit_logging=True,
    session_ttl_seconds=3600,
)

# Add middleware
app.add_middleware(
    FrappeAuthMiddleware,
    auth_bridge=auth_bridge,
    session_cookie_name="frappe_session",
    exempt_paths=["/", "/login", "/logout", "/docs", "/openapi.json"],
)

# Store auth bridge in app state for decorator access
app.state.frappe_auth_bridge = auth_bridge


# Request/Response models
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    session_id: str
    token: str
    user_email: str
    roles: list[str]


class UserResponse(BaseModel):
    email: str
    name: str
    full_name: str | None
    roles: list[str]


# Routes
@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "Frappe Auth Bridge FastAPI Example"}


@app.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, response: Response):
    """
    Login endpoint - authenticate with username and password.
    """
    try:
        # Authenticate with Frappe
        session = auth_bridge.login_with_password(credentials.username, credentials.password)

        # Set session cookie
        response.set_cookie(
            key="frappe_session",
            value=session.session_id,
            httponly=True,
            secure=True,  # Only over HTTPS in production
            samesite="strict",
            max_age=3600,
        )

        return LoginResponse(
            session_id=session.session_id,
            token=session.token,
            user_email=session.user.email,
            roles=session.user.roles,
        )

    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


@app.post("/logout")
async def logout(request: Request, response: Response):
    """Logout endpoint - invalidate session."""
    session_id = request.cookies.get("frappe_session")

    if session_id:
        try:
            auth_bridge.logout(session_id)
        except Exception:
            pass

    # Clear session cookie
    response.delete_cookie("frappe_session")

    return {"message": "Logged out successfully"}


@app.get("/me", response_model=UserResponse)
async def get_current_user(request: Request):
    """
    Get current authenticated user.
    Requires authentication via middleware.
    """
    if not hasattr(request.state, "user") or request.state.user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = request.state.user
    return UserResponse(
        email=user.email,
        name=user.name,
        full_name=user.full_name,
        roles=user.roles,
    )


@app.get("/secure")
async def secure_endpoint(request: Request):
    """
    Protected endpoint using middleware authentication.
    """
    if not hasattr(request.state, "user") or request.state.user is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = request.state.user
    return {
        "message": f"Hello, {user.full_name or user.email}!",
        "roles": user.roles,
        "access_level": "secure",
    }


@app.get("/admin-only")
async def admin_only_endpoint(request: Request):
    """
    Admin-only endpoint with role checking.
    """
    if not hasattr(request.state, "user") or request.state.user is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = request.state.user

    # Check if user has admin role
    if "Administrator" not in user.roles and "System Manager" not in user.roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    return {
        "message": "Welcome, administrator!",
        "user": user.email,
        "roles": user.roles,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
