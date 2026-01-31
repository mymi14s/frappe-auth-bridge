"""Tests for core authentication functionality."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from frappe_auth_bridge import FrappeAuthBridge, AuthenticationError, SessionExpiredError
from frappe_auth_bridge.models import User, Session, Permission
from frappe_auth_bridge.session import MemorySessionStore
from frappe_auth_bridge.security import EncryptionManager


@pytest.fixture
def auth_bridge():
    """Create FrappeAuthBridge instance for testing."""
    return FrappeAuthBridge(
        frappe_url="https://test.erpnext.com",
        enable_rate_limiting=False,
        enable_audit_logging=False,
        session_ttl_seconds=3600,
    )


@pytest.fixture
def mock_frappe_client():
    """Mock FrappeClient for testing."""
    with patch('frappe_auth_bridge.core.FrappeClient') as mock:
        client = Mock()
        client.sid = "test_session_token"
        
        # Mock requests session and cookies
        mock_session = Mock()
        mock_session.cookies = Mock()
        mock_session.cookies.get.return_value = "test_session_token"
        client.session = mock_session
        client.headers = {}
        
        client.get_doc = Mock(return_value={
            'email': 'test@example.com',
            'name': 'test@example.com',
            'full_name': 'Test User',
            'user_type': 'System User',
            'language': 'en',
        })
        client.get_list = Mock(return_value=[
            {'role': 'System Manager'},
            {'role': 'Sales User'},
        ])
        mock.return_value = client
        yield mock


def test_auth_bridge_initialization():
    """Test FrappeAuthBridge initialization."""
    auth = FrappeAuthBridge(
        frappe_url="https://test.erpnext.com",
        session_ttl_seconds=1800,
    )
    
    assert auth.frappe_url == "https://test.erpnext.com"
    assert auth.session_ttl_seconds == 1800
    assert auth.encryption is not None
    assert auth.session_store is not None
    assert auth.permission_cache is not None


def test_login_with_password_success(auth_bridge, mock_frappe_client):
    """Test successful login with password."""
    session = auth_bridge.login_with_password("test@example.com", "password")
    
    assert session.user.email == "test@example.com"
    assert session.user.full_name == "Test User"
    assert "System Manager" in session.user.roles
    assert "Sales User" in session.user.roles
    assert session.session_id is not None
    assert session.token is not None


def test_login_with_password_failure(auth_bridge):
    """Test login failure."""
    with patch('frappe_auth_bridge.core.FrappeClient') as mock:
        mock.return_value.login.side_effect = Exception("Invalid credentials")
        
        with pytest.raises(AuthenticationError):
            auth_bridge.login_with_password("bad@example.com", "wrong")


def test_refresh_token(auth_bridge, mock_frappe_client):
    """Test token refresh."""
    # Login first
    session = auth_bridge.login_with_password("test@example.com", "password")
    
    # Refresh token
    refreshed_session = auth_bridge.refresh_token(session.session_id)
    
    assert refreshed_session.session_id == session.session_id
    assert refreshed_session.last_refreshed_at is not None
    assert refreshed_session.expires_at > session.expires_at


def test_logout(auth_bridge, mock_frappe_client):
    """Test logout."""
    # Login first
    session = auth_bridge.login_with_password("test@example.com", "password")
    
    # Logout
    auth_bridge.logout(session.session_id)
    
    # Session should be deleted
    assert not auth_bridge.session_store.exists(session.session_id)


def test_session_expiry():
    """Test session expiration."""
    user = User(
        email="test@example.com",
        name="test",
        roles=["User"]
    )
    
    # Create expired session
    session = Session(
        session_id="test_id",
        token="test_token",
        user=user,
        expires_at=datetime.utcnow() - timedelta(hours=1)
    )
    
    assert session.is_expired is True


def test_session_needs_refresh():
    """Test session needs refresh check."""
    user = User(
        email="test@example.com",
        name="test",
        roles=["User"]
    )
    
    # Create session that needs refresh (within 5 minutes of expiry)
    session = Session(
        session_id="test_id",
        token="test_token",
        user=user,
        expires_at=datetime.utcnow() + timedelta(minutes=3)
    )
    
    assert session.needs_refresh is True


def test_rate_limiting():
    """Test rate limiting."""
    auth = FrappeAuthBridge(
        frappe_url="https://test.erpnext.com",
        enable_rate_limiting=True,
        enable_audit_logging=False,
    )
    
    # Should have rate limiter
    assert auth.rate_limiter is not None
    
    # Test rate limit check
    for i in range(30):
        auth.rate_limiter.is_allowed("test_user")
    
    # Next request should fail
    from frappe_auth_bridge.exceptions import RateLimitExceededError
    with pytest.raises(RateLimitExceededError):
        auth.rate_limiter.is_allowed("test_user")


def test_multi_tenant_configuration():
    """Test multi-tenant configuration."""
    from frappe_auth_bridge.models import TenantConfig
    
    # Create auth bridge with multi_tenant enabled
    auth_bridge = FrappeAuthBridge(
        frappe_url="https://test.erpnext.com",
        multi_tenant=True,
        enable_rate_limiting=False,
        enable_audit_logging=False,
    )
    
    tenant_config = TenantConfig(
        tenant_id="company_a",
        frappe_url="https://company-a.erpnext.com"
    )
    
    auth_bridge.add_tenant(tenant_config)
    
    assert "company_a" in auth_bridge._tenant_configs
    assert auth_bridge._get_frappe_url("company_a") == "https://company-a.erpnext.com"


def test_permission_validation(auth_bridge):
    """Test permission validation."""
    # This is a basic test - real implementation would fetch from Frappe
    user_email = "test@example.com"
    
    # Mock permission cache
    auth_bridge.permission_cache.set_user_permissions(user_email, [
        Permission(doctype="User", read=True, write=False)
    ])
    
    # Should have read permission
    assert auth_bridge.validate_permission(user_email, "User", "read")
    
    # Should not have write permission
    from frappe_auth_bridge.exceptions import PermissionDeniedError
    with pytest.raises(PermissionDeniedError):
        auth_bridge.validate_permission(user_email, "User", "write")
