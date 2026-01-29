"""Flask example application using frappe-auth-bridge."""

import os
from flask import Flask, request, jsonify, g
from frappe_auth_bridge import FrappeAuthBridge
from frappe_auth_bridge.middleware.flask import FrappeAuthMiddleware, auth_required

# Initialize Flask app
app = Flask(__name__)

# Initialize Frappe Auth Bridge
FRAPPE_URL = os.getenv("FRAPPE_URL", "https://example.erpnext.com")
auth_bridge = FrappeAuthBridge(
    frappe_url=FRAPPE_URL,
    enable_rate_limiting=True,
    enable_audit_logging=True,
    session_ttl_seconds=3600,
)

# Initialize middleware
middleware = FrappeAuthMiddleware(
    app=app,
    auth_bridge=auth_bridge,
    session_cookie_name="frappe_session",
    exempt_paths=["/", "/login", "/logout", "/health"]
)


@app.route("/")
def index():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "message": "Frappe Auth Bridge Flask Example"
    })


@app.route("/login", methods=["POST"])
def login():
    """Login endpoint - authenticate with username and password."""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400
    
    try:
        # Authenticate with Frappe
        session = auth_bridge.login_with_password(
            data['username'],
            data['password']
        )
        
        # Create response
        response = jsonify({
            "session_id": session.session_id,
            "token": session.token,
            "user_email": session.user.email,
            "roles": session.user.roles,
        })
        
        # Set session cookie
        response.set_cookie(
            "frappe_session",
            session.session_id,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=3600,
        )
        
        return response
        
    except Exception as e:
        return jsonify({"error": f"Authentication failed: {str(e)}"}), 401


@app.route("/logout", methods=["POST"])
def logout():
    """Logout endpoint - invalidate session."""
    session_id = request.cookies.get("frappe_session")
    
    if session_id:
        try:
            auth_bridge.logout(session_id)
        except Exception:
            pass
    
    response = jsonify({"message": "Logged out successfully"})
    response.delete_cookie("frappe_session")
    
    return response


@app.route("/me")
@auth_required
def get_current_user():
    """Get current authenticated user."""
    user = g.user
    return jsonify({
        "email": user.email,
        "name": user.name,
        "full_name": user.full_name,
        "roles": user.roles,
    })


@app.route("/secure")
@auth_required
def secure_endpoint():
    """Protected endpoint using decorator."""
    user = g.user
    return jsonify({
        "message": f"Hello, {user.full_name or user.email}!",
        "roles": user.roles,
        "access_level": "secure",
    })


@app.route("/admin-only")
@auth_required
def admin_only():
    """Admin-only endpoint with role checking."""
    user = g.user
    
    # Check if user has admin role
    if "Administrator" not in user.roles and "System Manager" not in user.roles:
        return jsonify({"error": "Admin access required"}), 403
    
    return jsonify({
        "message": "Welcome, administrator!",
        "user": user.email,
        "roles": user.roles,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
