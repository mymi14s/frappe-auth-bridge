"""Vanilla Python example using frappe-auth-bridge."""

import os

from frappe_auth_bridge import FrappeAuthBridge

# Initialize Frappe Auth Bridge
FRAPPE_URL = os.getenv("FRAPPE_URL", "https://example.erpnext.com")


def main():
    """Demonstrate vanilla Python usage."""

    # Create auth bridge
    auth = FrappeAuthBridge(
        frappe_url=FRAPPE_URL,
        enable_rate_limiting=True,
        enable_audit_logging=True,
    )

    print("=== Frappe Auth Bridge - Vanilla Python Example ===\n")

    # Login with username and password
    print("1. Logging in...")
    try:
        username = input("Enter username/email: ")
        password = input("Enter password: ")

        session = auth.login_with_password(username, password)

        print(f"\n✓ Login successful!")
        print(f"  Session ID: {session.session_id}")
        print(f"  User: {session.user.email}")
        print(f"  Roles: {', '.join(session.user.roles)}")
        print(f"  Expires: {session.expires_at}")

    except Exception as e:
        print(f"\n✗ Login failed: {e}")
        return

    # Access user information
    print("\n2. User Information:")
    print(f"  Email: {session.user.email}")
    print(f"  Name: {session.user.name}")
    print(f"  Full Name: {session.user.full_name}")
    print(f"  User Type: {session.user.user_type}")
    print(f"  Roles: {session.user.roles}")

    # Check permissions
    print("\n3. Checking permissions...")
    try:
        # Example: Check if user can read User doctype
        has_perm = auth.validate_permission(session.user.email, "User", "read")
        print(f"  ✓ User has 'read' permission for 'User' doctype")
    except Exception as e:
        print(f"  ✗ Permission check failed: {e}")

    # Refresh token
    print("\n4. Refreshing session...")
    try:
        refreshed_session = auth.refresh_token(session.session_id)
        print(f"  ✓ Session refreshed")
        print(f"  New expiry: {refreshed_session.expires_at}")
    except Exception as e:
        print(f"  ✗ Refresh failed: {e}")

    # Logout
    print("\n5. Logging out...")
    try:
        auth.logout(session.session_id)
        print("  ✓ Logged out successfully")
    except Exception as e:
        print(f"  ✗ Logout failed: {e}")

    print("\n=== Example Complete ===")


def example_with_api_key():
    """Example using API key authentication."""

    auth = FrappeAuthBridge(frappe_url=FRAPPE_URL)

    api_key = input("Enter API key: ")
    api_secret = input("Enter API secret: ")

    try:
        session = auth.authenticate_api_key(api_key, api_secret)
        print(f"\n✓ API key authentication successful!")
        print(f"  User: {session.user.email}")
        print(f"  Roles: {', '.join(session.user.roles)}")

        return session
    except Exception as e:
        print(f"\n✗ API key authentication failed: {e}")
        return None


def example_multi_tenant():
    """Example with multi-tenant setup."""
    from frappe_auth_bridge.models import TenantConfig

    # Create auth bridge with multi-tenant support
    auth = FrappeAuthBridge(frappe_url="https://default.erpnext.com", multi_tenant=True)

    # Add tenant configurations
    auth.add_tenant(TenantConfig(tenant_id="company_a", frappe_url="https://company-a.erpnext.com"))

    auth.add_tenant(TenantConfig(tenant_id="company_b", frappe_url="https://company-b.erpnext.com"))

    # Login to specific tenant
    try:
        session = auth.login_with_password("user@example.com", "password", tenant_id="company_a")
        print(f"Logged in to tenant: {session.tenant_id}")
        print(f"User: {session.user.email}")
    except Exception as e:
        print(f"Multi-tenant login failed: {e}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "api-key":
            example_with_api_key()
        elif sys.argv[1] == "multi-tenant":
            example_multi_tenant()
        else:
            print("Usage: python vanilla_example.py [api-key|multi-tenant]")
    else:
        main()
