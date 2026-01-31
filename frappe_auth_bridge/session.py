"""Session storage backends for frappe-auth-bridge."""

import json
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, Optional
import os
from pathlib import Path
from frappe_auth_bridge.models import Session
from frappe_auth_bridge.security import EncryptionManager
from frappe_auth_bridge.exceptions import (
    SessionExpiredError, 
    InvalidTokenError,
    AuthenticationError
)


class SessionStore(ABC):
    """Abstract base class for session storage."""
    
    def __init__(self, encryption_manager: EncryptionManager, ttl_seconds: int = 3600):
        """
        Initialize session store.
        
        Args:
            encryption_manager: Encryption manager instance
            ttl_seconds: Time-to-live for sessions in seconds (default 1 hour)
        """
        self.encryption = encryption_manager
        self.ttl_seconds = ttl_seconds
    
    @abstractmethod
    def save(self, session: Session) -> None:
        """Save a session."""
        pass
    
    @abstractmethod
    def get(self, session_id: str) -> Optional[Session]:
        """Retrieve a session by ID."""
        pass
    
    @abstractmethod
    def delete(self, session_id: str) -> None:
        """Delete a session by ID."""
        pass
    
    @abstractmethod
    def exists(self, session_id: str) -> bool:
        """Check if a session exists."""
        pass
    
    def _encrypt_session(self, session: Session) -> str:
        """Encrypt session data."""
        session_json = session.model_dump_json()
        return self.encryption.encrypt(session_json)
    
    def _decrypt_session(self, encrypted_data: str) -> Session:
        """Decrypt session data."""
        try:
            session_json = self.encryption.decrypt(encrypted_data)
            session_dict = json.loads(session_json)
            
            # Parse datetime fields
            for field in ['created_at', 'expires_at', 'last_refreshed_at']:
                if field in session_dict and session_dict[field]:
                    session_dict[field] = datetime.fromisoformat(
                        session_dict[field].replace('Z', '+00:00')
                    )
            
            session = Session(**session_dict)
            
            # Check if session is expired
            if session.is_expired:
                raise SessionExpiredError(f"Session {session.session_id} has expired")
            
            return session
        except json.JSONDecodeError as e:
            raise InvalidTokenError(f"Invalid session data: {str(e)}")


class MemorySessionStore(SessionStore):
    """In-memory session storage backend."""
    
    def __init__(self, encryption_manager: EncryptionManager, ttl_seconds: int = 3600):
        super().__init__(encryption_manager, ttl_seconds)
        self._store: Dict[str, str] = {}
    
    def save(self, session: Session) -> None:
        """Save session to memory."""
        encrypted = self._encrypt_session(session)
        self._store[session.session_id] = encrypted
    
    def get(self, session_id: str) -> Optional[Session]:
        """Get session from memory."""
        encrypted = self._store.get(session_id)
        if encrypted:
            try:
                return self._decrypt_session(encrypted)
            except SessionExpiredError:
                # Clean up expired session
                self.delete(session_id)
                raise
        return None
    
    def delete(self, session_id: str) -> None:
        """Delete session from memory."""
        self._store.pop(session_id, None)
    
    def exists(self, session_id: str) -> bool:
        """Check if session exists in memory."""
        return session_id in self._store
    
    def clear_all(self) -> None:
        """Clear all sessions (useful for testing)."""
        self._store.clear()


class RedisSessionStore(SessionStore):
    """Redis session storage backend."""
    
    def __init__(self, encryption_manager: EncryptionManager, ttl_seconds: int = 3600, 
                 redis_url: str = "redis://localhost:6379"):
        super().__init__(encryption_manager, ttl_seconds)
        
        try:
            import redis
            self._redis = redis.from_url(redis_url, decode_responses=True)
        except ImportError:
            raise ImportError(
                "Redis support requires the 'redis' package. "
                "Install with: pip install frappe-auth-bridge[redis]"
            )
    
    def _key(self, session_id: str) -> str:
        """Generate Redis key for session."""
        return f"frappe_auth:session:{session_id}"
    
    def save(self, session: Session) -> None:
        """Save session to Redis."""
        encrypted = self._encrypt_session(session)
        key = self._key(session.session_id)
        self._redis.setex(key, self.ttl_seconds, encrypted)
    
    def get(self, session_id: str) -> Optional[Session]:
        """Get session from Redis."""
        key = self._key(session_id)
        encrypted = self._redis.get(key)
        if encrypted:
            try:
                return self._decrypt_session(encrypted)
            except SessionExpiredError:
                # Clean up expired session
                self.delete(session_id)
                raise
        return None
    
    def delete(self, session_id: str) -> None:
        """Delete session from Redis."""
        key = self._key(session_id)
        self._redis.delete(key)
    
    def exists(self, session_id: str) -> bool:
        """Check if session exists in Redis."""
        key = self._key(session_id)
        return self._redis.exists(key) > 0


class FileSessionStore(SessionStore):
    """File-based session storage backend."""
    
    def __init__(self, encryption_manager: EncryptionManager, ttl_seconds: int = 3600, 
                 storage_path: str = "/tmp/frappe_auth_sessions"):
        super().__init__(encryption_manager, ttl_seconds)
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
    
    def _file_path(self, session_id: str) -> Path:
        """Get file path for session ID."""
        return self.storage_path / f"session_{session_id}.json"
    
    def save(self, session: Session) -> None:
        """Save session to file."""
        encrypted = self._encrypt_session(session)
        file_path = self._file_path(session.session_id)
        file_path.write_text(encrypted)
    
    def get(self, session_id: str) -> Optional[Session]:
        """Get session from file."""
        file_path = self._file_path(session_id)
        if file_path.exists():
            try:
                encrypted = file_path.read_text()
                return self._decrypt_session(encrypted)
            except SessionExpiredError:
                self.delete(session_id)
                raise
            except Exception:
                self.delete(session_id)
                return None
        return None
    
    def delete(self, session_id: str) -> None:
        """Delete session file."""
        file_path = self._file_path(session_id)
        file_path.unlink(missing_ok=True)
    
    def exists(self, session_id: str) -> bool:
        """Check if session file exists."""
        return self._file_path(session_id).exists()
    
    def clear_all(self) -> None:
        """Clear all session files."""
        for f in self.storage_path.glob("session_*.json"):
            f.unlink()
