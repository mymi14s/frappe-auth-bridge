"""Audit logging for frappe-auth-bridge."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


class AuditLogger:
    """Audit logger for authentication events."""

    # Sensitive fields to redact
    SENSITIVE_FIELDS = {"password", "token", "secret", "api_key", "api_secret", "sid"}

    def __init__(self, log_file: Optional[str] = None, enable_console: bool = True):
        """
        Initialize audit logger.

        Args:
            log_file: Optional path to log file
            enable_console: Whether to enable console logging
        """
        self.logger = logging.getLogger("frappe_auth_bridge.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        # Remove existing handlers
        self.logger.handlers.clear()

        # Add file handler if specified
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(self._get_formatter())
            self.logger.addHandler(file_handler)

        # Add console handler if enabled
        if enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(self._get_formatter())
            self.logger.addHandler(console_handler)

    def _get_formatter(self) -> logging.Formatter:
        """Get log formatter."""
        return logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )

    def _redact_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive fields from log data."""
        redacted = data.copy()
        for key in redacted:
            if key.lower() in self.SENSITIVE_FIELDS:
                redacted[key] = "***REDACTED***"
            elif isinstance(redacted[key], dict):
                redacted[key] = self._redact_sensitive_data(redacted[key])
        return redacted

    def log_event(
        self,
        event_type: str,
        user: Optional[str] = None,
        success: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Log an audit event.

        Args:
            event_type: Type of event (login_success, login_failure, etc.)
            user: User identifier
            success: Whether the event was successful
            metadata: Additional event metadata
        """
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user": user,
            "success": success,
            "metadata": self._redact_sensitive_data(metadata or {}),
        }

        log_message = json.dumps(log_data)

        if success:
            self.logger.info(log_message)
        else:
            self.logger.warning(log_message)

    def login_success(self, user: str, metadata: Optional[Dict[str, Any]] = None):
        """Log successful login."""
        self.log_event("login_success", user=user, success=True, metadata=metadata)

    def login_failure(self, user: str, reason: str, metadata: Optional[Dict[str, Any]] = None):
        """Log failed login."""
        meta = metadata or {}
        meta["reason"] = reason
        self.log_event("login_failure", user=user, success=False, metadata=meta)

    def token_refresh(self, user: str, metadata: Optional[Dict[str, Any]] = None):
        """Log token refresh."""
        self.log_event("token_refresh", user=user, success=True, metadata=metadata)

    def logout(self, user: str, metadata: Optional[Dict[str, Any]] = None):
        """Log logout."""
        self.log_event("logout", user=user, success=True, metadata=metadata)

    def permission_fetch(self, user: str, metadata: Optional[Dict[str, Any]] = None):
        """Log permission fetch."""
        self.log_event("permission_fetch", user=user, success=True, metadata=metadata)

    def suspicious_activity(
        self, user: Optional[str], reason: str, metadata: Optional[Dict[str, Any]] = None
    ):
        """Log suspicious activity."""
        meta = metadata or {}
        meta["reason"] = reason
        self.log_event("suspicious_activity", user=user, success=False, metadata=meta)
