"""Tests for session management."""

from datetime import datetime, timedelta

import pytest

from frappe_auth_bridge.exceptions import SessionExpiredError
from frappe_auth_bridge.models import Session, User
from frappe_auth_bridge.security import EncryptionManager
from frappe_auth_bridge.session import MemorySessionStore, SessionStore


@pytest.fixture
def encryption_manager():
    """Create encryption manager for testing."""
    return EncryptionManager()


@pytest.fixture
def session_store(encryption_manager):
    """Create session store for testing."""
    return MemorySessionStore(encryption_manager, ttl_seconds=3600)


@pytest.fixture
def test_user():
    """Create test user."""
    return User(
        email="test@example.com",
        name="test",
        full_name="Test User",
        roles=["System Manager", "User"],
    )


@pytest.fixture
def test_session(test_user):
    """Create test session."""
    return Session(
        session_id="test_session_id",
        token="test_token",
        user=test_user,
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )


def test_session_creation(test_session):
    """Test session creation."""
    assert test_session.session_id == "test_session_id"
    assert test_session.token == "test_token"
    assert test_session.user.email == "test@example.com"
    assert not test_session.is_expired


def test_session_expiration():
    """Test session expiration."""
    user = User(email="test@example.com", name="test", roles=[])

    # Create expired session
    expired_session = Session(
        session_id="expired",
        token="token",
        user=user,
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )

    assert expired_session.is_expired


def test_session_needs_refresh():
    """Test session refresh detection."""
    user = User(email="test@example.com", name="test", roles=[])

    # Session expiring in 3 minutes - needs refresh
    session = Session(
        session_id="test",
        token="token",
        user=user,
        expires_at=datetime.utcnow() + timedelta(minutes=3),
    )

    assert session.needs_refresh


def test_memory_session_store_save_and_get(session_store, test_session):
    """Test saving and retrieving sessions."""
    # Save session
    session_store.save(test_session)

    # Retrieve session
    retrieved = session_store.get(test_session.session_id)

    assert retrieved is not None
    assert retrieved.session_id == test_session.session_id
    assert retrieved.user.email == test_session.user.email


def test_memory_session_store_delete(session_store, test_session):
    """Test deleting sessions."""
    # Save session
    session_store.save(test_session)
    assert session_store.exists(test_session.session_id)

    # Delete session
    session_store.delete(test_session.session_id)
    assert not session_store.exists(test_session.session_id)


def test_memory_session_store_expired_session(session_store, test_user):
    """Test handling of expired sessions."""
    # Create expired session
    expired_session = Session(
        session_id="expired",
        token="token",
        user=test_user,
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )

    # Save it
    session_store.save(expired_session)

    # Getting it should raise SessionExpiredError
    with pytest.raises(SessionExpiredError):
        session_store.get("expired")

    # Session should be cleaned up
    assert not session_store.exists("expired")


def test_session_encryption(encryption_manager, test_session):
    """Test session encryption and decryption."""
    store = MemorySessionStore(encryption_manager, ttl_seconds=3600)

    # Encrypt session
    encrypted = store._encrypt_session(test_session)
    assert encrypted != test_session.model_dump_json()

    # Decrypt session
    decrypted = store._decrypt_session(encrypted)
    assert decrypted.session_id == test_session.session_id
    assert decrypted.user.email == test_session.user.email


def test_session_exists(session_store, test_session):
    """Test session existence check."""
    assert not session_store.exists(test_session.session_id)

    session_store.save(test_session)
    assert session_store.exists(test_session.session_id)

    session_store.delete(test_session.session_id)
    assert not session_store.exists(test_session.session_id)


def test_session_clear_all(session_store, test_user):
    """Test clearing all sessions."""
    # Create multiple sessions
    for i in range(5):
        session = Session(
            session_id=f"session_{i}",
            token=f"token_{i}",
            user=test_user,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        session_store.save(session)

    # All should exist
    for i in range(5):
        assert session_store.exists(f"session_{i}")

    # Clear all
    session_store.clear_all()

    # None should exist
    for i in range(5):
        assert not session_store.exists(f"session_{i}")
