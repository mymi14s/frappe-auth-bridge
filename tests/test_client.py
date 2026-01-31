"""Test FrappeClient integration."""

import pytest
from unittest.mock import Mock, patch
from frappe_auth_bridge import FrappeAuthBridge
from frappe_auth_bridge.exceptions import AuthenticationError


def test_client_after_login():
    """Test that client is available after login."""
    with patch('frappe_auth_bridge.core.FrappeClient') as MockClient:
        mock_client = Mock()
        mock_client.sid = "test_session_token"
        
        # Mock requests session and cookies
        mock_session = Mock()
        mock_session.cookies = Mock()
        mock_session.cookies.get.return_value = "test_session_token"
        mock_client.session = mock_session
        mock_client.headers = {}
        
        mock_client.get_doc.return_value = {
            'email': 'test@example.com',
            'name': 'test@example.com',
            'full_name': 'Test User',
        }
        mock_client.get_list.return_value = [{'role': 'System User'}]
        MockClient.return_value = mock_client
        
        auth = FrappeAuthBridge(
            frappe_url="https://test.erpnext.com",
            enable_rate_limiting=False,
            enable_audit_logging=False,
        )
        
        session = auth.login_with_password("test@example.com", "password")
        
        assert auth._client is not None
        assert auth.client == mock_client
        
        mock_client.login.assert_called_once_with("test@example.com", "password")


def test_set_client_credentials():
    """Test setting client credentials."""
    auth = FrappeAuthBridge(
        frappe_url="https://test.erpnext.com",
        enable_rate_limiting=False,
        enable_audit_logging=False,
    )
    
    auth.set_client_credentials("user@example.com", "password")
    
    assert auth._client_credentials == {
        'username': 'user@example.com',
        'password': 'password',
        'tenant_id': None
    }


def test_set_client_api_key():
    """Test setting API key for client."""
    auth = FrappeAuthBridge(
        frappe_url="https://test.erpnext.com",
        enable_rate_limiting=False,
        enable_audit_logging=False,
    )
    
    auth.set_client_api_key("api_key", "api_secret")
    
    assert auth._client_credentials == {
        'api_key': 'api_key',
        'api_secret': 'api_secret',
        'tenant_id': None
    }


def test_client_without_credentials():
    """Test that client raises error without credentials."""
    auth = FrappeAuthBridge(
        frappe_url="https://test.erpnext.com",
        enable_rate_limiting=False,
        enable_audit_logging=False,
    )
    
    with pytest.raises(RuntimeError, match="No client credentials set"):
        _ = auth.client


def test_get_client_with_username_password():
    """Test get_client with username/password."""
    with patch('frappe_auth_bridge.core.FrappeClient') as MockClient:
        mock_client = Mock()
        MockClient.return_value = mock_client
        
        auth = FrappeAuthBridge(
            frappe_url="https://test.erpnext.com",
            enable_rate_limiting=False,
            enable_audit_logging=False,
        )
        
        client = auth.get_client(username="user@example.com", password="password")
        
        assert client == mock_client
        mock_client.login.assert_called_once_with("user@example.com", "password")


def test_get_client_with_api_key():
    """Test get_client with API key."""
    with patch('frappe_auth_bridge.core.FrappeClient') as MockClient:
        mock_client = Mock()
        MockClient.return_value = mock_client
        
        auth = FrappeAuthBridge(
            frappe_url="https://test.erpnext.com",
            enable_rate_limiting=False,
            enable_audit_logging=False,
        )
        
        client = auth.get_client(api_key="key", api_secret="secret")
        
        assert client == mock_client
        mock_client.authenticate.assert_called_once_with("key", "secret")


def test_get_client_without_credentials():
    """Test get_client raises error without credentials."""
    auth = FrappeAuthBridge(
        frappe_url="https://test.erpnext.com",
        enable_rate_limiting=False,
        enable_audit_logging=False,
    )
    
    with pytest.raises(AuthenticationError, match="Must provide either"):
        auth.get_client()
