"""Tests for security features."""

import os

import pytest

from frappe_auth_bridge.exceptions import (InvalidTokenError,
                                           RateLimitExceededError)
from frappe_auth_bridge.security import (EncryptionManager,
                                         TokenBucketRateLimiter,
                                         generate_secure_token,
                                         get_secret_from_env)


def test_encryption_manager():
    """Test encryption manager."""
    manager = EncryptionManager()

    # Test encryption/decryption
    plaintext = "secret_data"
    encrypted = manager.encrypt(plaintext)

    assert encrypted != plaintext
    assert manager.decrypt(encrypted) == plaintext


def test_encryption_with_custom_key():
    """Test encryption with custom key."""
    from cryptography.fernet import Fernet

    custom_key = Fernet.generate_key()
    manager = EncryptionManager(custom_key)

    plaintext = "test_data"
    encrypted = manager.encrypt(plaintext)
    decrypted = manager.decrypt(encrypted)

    assert decrypted == plaintext


def test_encryption_invalid_data():
    """Test decryption of invalid data."""
    manager = EncryptionManager()

    with pytest.raises(InvalidTokenError):
        manager.decrypt("invalid_encrypted_data")


def test_token_bucket_rate_limiter():
    """Test token bucket rate limiter."""
    limiter = TokenBucketRateLimiter(rate=10, capacity=10)

    # First 10 requests should succeed
    for i in range(10):
        assert limiter.is_allowed("user_1")

    # 11th request should fail
    with pytest.raises(RateLimitExceededError):
        limiter.is_allowed("user_1")


def test_rate_limiter_multiple_keys():
    """Test rate limiter with multiple keys."""
    limiter = TokenBucketRateLimiter(rate=5, capacity=5)

    # Fill bucket for user_1
    for i in range(5):
        assert limiter.is_allowed("user_1")

    # user_2 should still have tokens
    for i in range(5):
        assert limiter.is_allowed("user_2")

    # Both should be rate limited now
    with pytest.raises(RateLimitExceededError):
        limiter.is_allowed("user_1")

    with pytest.raises(RateLimitExceededError):
        limiter.is_allowed("user_2")


def test_rate_limiter_reset():
    """Test rate limiter reset."""
    limiter = TokenBucketRateLimiter(rate=5, capacity=5)

    # Use all tokens
    for i in range(5):
        limiter.is_allowed("user_1")

    # Should be rate limited
    with pytest.raises(RateLimitExceededError):
        limiter.is_allowed("user_1")

    # Reset
    limiter.reset("user_1")

    # Should work again
    assert limiter.is_allowed("user_1")


def test_generate_secure_token():
    """Test secure token generation."""
    token1 = generate_secure_token()
    token2 = generate_secure_token()

    # Tokens should be different
    assert token1 != token2

    # Should be hex strings
    assert all(c in "0123456789abcdef" for c in token1)
    assert all(c in "0123456789abcdef" for c in token2)

    # Default length is 32 bytes = 64 hex chars
    assert len(token1) == 64
    assert len(token2) == 64


def test_generate_secure_token_custom_length():
    """Test secure token generation with custom length."""
    token = generate_secure_token(length=16)
    assert len(token) == 32  # 16 bytes = 32 hex chars


def test_get_secret_from_env():
    """Test getting secret from environment."""
    # Set env variable
    os.environ["TEST_SECRET"] = "secret_value"

    # Should retrieve it
    assert get_secret_from_env("TEST_SECRET") == "secret_value"

    # Clean up
    del os.environ["TEST_SECRET"]


def test_get_secret_from_env_with_default():
    """Test getting secret with default value."""
    secret = get_secret_from_env("NONEXISTENT_SECRET", default="default_value")
    assert secret == "default_value"


def test_get_secret_from_env_missing():
    """Test getting secret that doesn't exist."""
    with pytest.raises(ValueError):
        get_secret_from_env("NONEXISTENT_SECRET")


def test_encryption_key_from_env():
    """Test encryption manager using env variable."""
    from cryptography.fernet import Fernet

    # Generate valid Fernet key
    valid_key = Fernet.generate_key()
    os.environ["FRAPPE_AUTH_SECRET_KEY"] = valid_key.decode()

    manager = EncryptionManager()
    plaintext = "test"
    encrypted = manager.encrypt(plaintext)
    assert manager.decrypt(encrypted) == plaintext

    del os.environ["FRAPPE_AUTH_SECRET_KEY"]
