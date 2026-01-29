"""Caching utilities for frappe-auth-bridge."""

from typing import Any, Callable, Optional
from datetime import timedelta
from cachetools import TTLCache
from frappe_auth_bridge.security import EncryptionManager


class EncryptedCache:
    """TTL-based cache with encrypted storage."""
    
    def __init__(self, maxsize: int = 1000, ttl: int = 3600, 
                 encryption_manager: Optional[EncryptionManager] = None):
        """
        Initialize encrypted cache.
        
        Args:
            maxsize: Maximum number of items in cache
            ttl: Time-to-live in seconds
            encryption_manager: Optional encryption manager for encrypting values
        """
        self._cache = TTLCache(maxsize=maxsize, ttl=ttl)
        self._encryption = encryption_manager
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        encrypted_value = self._cache.get(key)
        if encrypted_value is None:
            return default
        
        if self._encryption:
            try:
                return self._encryption.decrypt(encrypted_value)
            except Exception:
                self._cache.pop(key, None)
                return default
        return encrypted_value
    
    def set(self, key: str, value: Any) -> None:
        """Set value in cache."""
        if self._encryption and isinstance(value, str):
            encrypted_value = self._encryption.encrypt(value)
            self._cache[key] = encrypted_value
        else:
            self._cache[key] = value
    
    def delete(self, key: str) -> None:
        """Delete value from cache."""
        self._cache.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
    
    def __contains__(self, key: str) -> bool:
        """Check if key exists in cache."""
        return key in self._cache


class PermissionCache:
    """Specialized cache for user permissions."""
    
    def __init__(self, ttl: int = 3600):
        """
        Initialize permission cache.
        
        Args:
            ttl: Time-to-live in seconds (default 1 hour)
        """
        self._cache = TTLCache(maxsize=10000, ttl=ttl)
    
    def get_user_roles(self, user_email: str) -> Optional[list]:
        """Get cached user roles."""
        return self._cache.get(f"roles:{user_email}")
    
    def set_user_roles(self, user_email: str, roles: list) -> None:
        """Cache user roles."""
        self._cache[f"roles:{user_email}"] = roles
    
    def get_user_permissions(self, user_email: str) -> Optional[list]:
        """Get cached user permissions."""
        return self._cache.get(f"permissions:{user_email}")
    
    def set_user_permissions(self, user_email: str, permissions: list) -> None:
        """Cache user permissions."""
        self._cache[f"permissions:{user_email}"] = permissions
    
    def invalidate_user(self, user_email: str) -> None:
        """Invalidate all cached data for a user."""
        self._cache.pop(f"roles:{user_email}", None)
        self._cache.pop(f"permissions:{user_email}", None)
    
    def clear(self) -> None:
        """Clear all cached permissions."""
        self._cache.clear()
