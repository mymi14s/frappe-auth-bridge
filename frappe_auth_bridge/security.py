"""Security utilities for frappe-auth-bridge."""

import os
import secrets
import time
from typing import Optional
from cryptography.fernet import Fernet
from frappe_auth_bridge.exceptions import InvalidTokenError, RateLimitExceededError


class EncryptionManager:
    """Manages encryption and decryption of sensitive data."""
    
    def __init__(self, secret_key: Optional[str] = None):
        """
        Initialize encryption manager.
        
        Args:
            secret_key: Optional Fernet key. If not provided, will load from
                       FRAPPE_AUTH_SECRET_KEY environment variable or generate new one.
        """
        if secret_key:
            self._key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        else:
            key_env = os.getenv('FRAPPE_AUTH_SECRET_KEY')
            if key_env:
                self._key = key_env.encode()
            else:
                # Generate new key for development (should be persisted in production)
                self._key = Fernet.generate_key()
        
        self._fernet = Fernet(self._key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt a string."""
        return self._fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt a string."""
        try:
            return self._fernet.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            raise InvalidTokenError(f"Failed to decrypt data: {str(e)}")
    
    def get_key(self) -> bytes:
        """Get the encryption key (for persistence)."""
        return self._key


class TokenBucketRateLimiter:
    """Token bucket rate limiter implementation."""
    
    def __init__(self, rate: int, capacity: int):
        """
        Initialize rate limiter.
        
        Args:
            rate: Number of tokens added per minute
            capacity: Maximum number of tokens in bucket
        """
        self.rate = rate / 60.0  # Convert to per-second rate
        self.capacity = capacity
        self._buckets: dict[str, dict] = {}
    
    def is_allowed(self, key: str) -> bool:
        """
        Check if request is allowed for given key.
        
        Args:
            key: Identifier for rate limiting (e.g., user ID, IP address)
            
        Returns:
            True if request is allowed, False otherwise
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded
        """
        current_time = time.time()
        
        if key not in self._buckets:
            self._buckets[key] = {
                'tokens': self.capacity,
                'last_update': current_time
            }
        
        bucket = self._buckets[key]
        time_passed = current_time - bucket['last_update']
        
        # Add new tokens based on time passed
        bucket['tokens'] = min(
            self.capacity,
            bucket['tokens'] + time_passed * self.rate
        )
        bucket['last_update'] = current_time
        
        # Check if we have tokens available
        if bucket['tokens'] >= 1:
            bucket['tokens'] -= 1
            return True
        else:
            raise RateLimitExceededError(f"Rate limit exceeded for key: {key}")
    
    def reset(self, key: str):
        """Reset rate limit for a key."""
        if key in self._buckets:
            del self._buckets[key]


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Args:
        length: Length of the token in bytes
        
    Returns:
        Hex-encoded secure random token
    """
    return secrets.token_hex(length)


def get_secret_from_env(key: str, default: Optional[str] = None) -> str:
    """
    Safely retrieve secret from environment variables.
    
    Args:
        key: Environment variable name
        default: Default value if not found
        
    Returns:
        Secret value
        
    Raises:
        ValueError: If secret not found and no default provided
    """
    value = os.getenv(key, default)
    if value is None:
        raise ValueError(f"Required environment variable '{key}' not set")
    return value
