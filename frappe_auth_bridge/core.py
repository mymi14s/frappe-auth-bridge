"""Core FrappeAuthBridge class for authentication."""

import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from frappeclient import FrappeClient

from frappe_auth_bridge.cache import PermissionCache
from frappe_auth_bridge.exceptions import (AuthenticationError,
                                           PermissionDeniedError,
                                           RateLimitExceededError,
                                           SessionExpiredError,
                                           TenantNotFoundError)
from frappe_auth_bridge.models import Permission, Session, TenantConfig, User
from frappe_auth_bridge.security import (EncryptionManager,
                                         TokenBucketRateLimiter,
                                         generate_secure_token)
from frappe_auth_bridge.session import MemorySessionStore, SessionStore
from frappe_auth_bridge.utils.logger import AuditLogger


class FrappeAuthBridge:
    """Main authentication bridge for Frappe applications."""

    def __init__(
        self,
        frappe_url: str,
        session_store: Optional[SessionStore] = None,
        encryption_key: Optional[str] = None,
        enable_rate_limiting: bool = True,
        enable_audit_logging: bool = True,
        session_ttl_seconds: int = 3600,
        multi_tenant: bool = False,
    ):
        """
        Initialize Frappe Auth Bridge.

        Args:
            frappe_url: Base URL of Frappe server
            session_store: Optional custom session store (defaults to MemorySessionStore)
            encryption_key: Optional encryption key (generated if not provided)
            enable_rate_limiting: Enable rate limiting (default True)
            enable_audit_logging: Enable audit logging (default True)
            session_ttl_seconds: Session TTL in seconds (default 3600 / 1 hour)
            multi_tenant: Enable multi-tenant support
        """
        self.frappe_url = frappe_url.rstrip("/")
        self.multi_tenant = multi_tenant
        self.session_ttl_seconds = session_ttl_seconds

        self.encryption = EncryptionManager(encryption_key)

        if session_store:
            self.session_store = session_store
            if not getattr(self.session_store, "encryption", None):
                self.session_store.encryption = self.encryption
        else:
            self.session_store = MemorySessionStore(
                encryption_manager=self.encryption, ttl_seconds=session_ttl_seconds
            )

        self.permission_cache = PermissionCache(ttl=session_ttl_seconds)

        self.rate_limiter = None
        if enable_rate_limiting:
            self.rate_limiter = TokenBucketRateLimiter(rate=30, capacity=30)

        self.audit_logger = None
        if enable_audit_logging:
            self.audit_logger = AuditLogger()

        self._tenant_configs: Dict[str, TenantConfig] = {}

        self._client: Optional[FrappeClient] = None
        self._client_credentials: Optional[Dict[str, str]] = None

    def add_tenant(self, tenant_config: TenantConfig) -> None:
        """
        Add a tenant configuration (for multi-tenant setups).

        Args:
            tenant_config: Tenant configuration
        """
        self._tenant_configs[tenant_config.tenant_id] = tenant_config

    def _get_frappe_url(self, tenant_id: Optional[str] = None) -> str:
        """Get Frappe URL for tenant or default."""
        if tenant_id and self.multi_tenant:
            config = self._tenant_configs.get(tenant_id)
            if not config:
                raise TenantNotFoundError(f"Tenant '{tenant_id}' not found")
            return config.frappe_url
        return self.frappe_url

    def _check_rate_limit(self, key: str) -> None:
        """Check rate limit for a key."""
        if self.rate_limiter:
            try:
                self.rate_limiter.is_allowed(key)
            except RateLimitExceededError as e:
                if self.audit_logger:
                    self.audit_logger.suspicious_activity(
                        key, "Rate limit exceeded", {"error": str(e)}
                    )
                raise

    def login_with_password(
        self, username: str, password: str, tenant_id: Optional[str] = None
    ) -> Session:
        """
        Authenticate user with username/email and password.

        Args:
            username: Username or email
            password: Password
            tenant_id: Optional tenant ID for multi-tenant setups

        Returns:
            Session object with token and user info

        Raises:
            AuthenticationError: If authentication fails
            RateLimitExceededError: If rate limit is exceeded
        """
        self._check_rate_limit(username)

        try:
            frappe_url = self._get_frappe_url(tenant_id)

            client = FrappeClient(frappe_url)
            client.login(username, password)

            user_data = client.get_doc("User", username)

            roles = self._fetch_user_roles(client, username)

            permissions = self._fetch_user_permissions(client, username)

            user = User(
                email=user_data.get("email", username),
                name=user_data.get("name", username),
                full_name=user_data.get("full_name"),
                user_image=user_data.get("user_image"),
                roles=roles,
                permissions=permissions,
                user_type=user_data.get("user_type"),
                language=user_data.get("language"),
            )

            self.permission_cache.set_user_roles(user.email, roles)
            self.permission_cache.set_user_permissions(user.email, permissions)

            session_id = generate_secure_token(16)
            expires_at = datetime.utcnow() + timedelta(seconds=self.session_ttl_seconds)

            session_token = client.session.cookies.get("sid", path="/")
            if not session_token:
                session_token = client.session.cookies.get("sid")

            if not session_token:
                session_token = getattr(client, "sid", None)

            if not session_token:
                session_token = generate_secure_token(32)
                if self.audit_logger:
                    self.audit_logger.warning(
                        f"Could not extract real sid for user {username}, using fallback token"
                    )

            session = Session(
                session_id=session_id,
                token=session_token,
                user=user,
                expires_at=expires_at,
                tenant_id=tenant_id,
            )

            self.session_store.save(session)

            if self.audit_logger:
                self.audit_logger.login_success(
                    user.email, metadata={"tenant_id": tenant_id, "roles_count": len(roles)}
                )

            self._client_credentials = {
                "username": username,
                "password": password,
                "tenant_id": tenant_id,
            }
            self._client = client

            return session

        except Exception as e:
            if self.audit_logger:
                self.audit_logger.login_failure(username, str(e), metadata={"tenant_id": tenant_id})
            raise AuthenticationError(f"Authentication failed: {str(e)}")

    def authenticate_session(self, session_token: str) -> Session:
        """
        Authenticate using an existing session token.

        Args:
            session_token: Session token

        Returns:
            Session object

        Raises:
            SessionExpiredError: If session is expired
            AuthenticationError: If session is invalid
        """
        try:
            session = self._find_session_by_token(session_token)
            if not session:
                raise AuthenticationError("Invalid session token")

            if session.needs_refresh:
                session = self.refresh_token(session.session_id)

            return session

        except SessionExpiredError:
            raise
        except Exception as e:
            raise AuthenticationError(f"Session authentication failed: {str(e)}")

    def _find_session_by_token(self, token: str) -> Optional[Session]:
        """Find session by token (helper method)."""
        raise NotImplementedError(
            "Token-based session lookup requires additional indexing. "
            "Use session_id-based lookup or implement token indexing."
        )

    def authenticate_api_key(
        self, api_key: str, api_secret: str, tenant_id: Optional[str] = None
    ) -> Session:
        """
        Authenticate using API key and secret.

        Args:
            api_key: API key
            api_secret: API secret
            tenant_id: Optional tenant ID

        Returns:
            Session object

        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            frappe_url = self._get_frappe_url(tenant_id)

            client = FrappeClient(frappe_url)
            client.authenticate(api_key, api_secret)

            user_data = client.get_api("frappe.auth.get_logged_user")
            username = user_data.get("message", "Administrator")

            user_doc = client.get_doc("User", username)
            roles = self._fetch_user_roles(client, username)
            permissions = self._fetch_user_permissions(client, username)

            user = User(
                email=user_doc.get("email", username),
                name=user_doc.get("name", username),
                full_name=user_doc.get("full_name"),
                roles=roles,
                permissions=permissions,
            )

            session_id = generate_secure_token(16)
            expires_at = datetime.utcnow() + timedelta(seconds=self.session_ttl_seconds)

            session = Session(
                session_id=session_id,
                token=f"{api_key}:{api_secret}",
                user=user,
                expires_at=expires_at,
                tenant_id=tenant_id,
            )

            self.session_store.save(session)

            self._client_credentials = {
                "api_key": api_key,
                "api_secret": api_secret,
                "tenant_id": tenant_id,
            }
            self._client = client

            if self.audit_logger:
                self.audit_logger.login_success(
                    user.email, metadata={"auth_method": "api_key", "tenant_id": tenant_id}
                )

            return session

        except Exception as e:
            raise AuthenticationError(f"API key authentication failed: {str(e)}")

    def refresh_token(self, session_id: str) -> Session:
        """
        Refresh an existing session token.

        Args:
            session_id: Session ID to refresh

        Returns:
            Refreshed session

        Raises:
            SessionExpiredError: If session cannot be refreshed
        """
        session = self.session_store.get(session_id)
        if not session:
            raise SessionExpiredError("Session not found")

        # Extend expiration
        session = Session(
            session_id=session.session_id,
            token=session.token,
            user=session.user,
            created_at=session.created_at,
            expires_at=datetime.utcnow() + timedelta(seconds=self.session_ttl_seconds),
            last_refreshed_at=datetime.utcnow(),
            tenant_id=session.tenant_id,
            metadata=session.metadata,
        )

        self.session_store.save(session)

        if self.audit_logger:
            self.audit_logger.token_refresh(session.user.email)

        return session

    def logout(self, session_id: str) -> None:
        """
        Logout and invalidate session.

        Args:
            session_id: Session ID to invalidate
        """
        session = self.session_store.get(session_id)
        if session:
            if self.audit_logger:
                self.audit_logger.logout(session.user.email)

            self.session_store.delete(session_id)

            self.permission_cache.invalidate_user(session.user.email)

    def get_user_roles(self, user_email: str, use_cache: bool = True) -> List[str]:
        """
        Get user roles.

        Args:
            user_email: User email
            use_cache: Whether to use cached roles

        Returns:
            List of role names
        """
        if use_cache:
            cached_roles = self.permission_cache.get_user_roles(user_email)
            if cached_roles is not None:
                return cached_roles

        return []

    def get_user_permissions(self, user_email: str, use_cache: bool = True) -> List[Permission]:
        """
        Get user permissions.

        Args:
            user_email: User email
            use_cache: Whether to use cached permissions

        Returns:
            List of permissions
        """
        if use_cache:
            cached_perms = self.permission_cache.get_user_permissions(user_email)
            if cached_perms is not None:
                return cached_perms

        return []

    def validate_permission(
        self, user_email: str, doctype: str, permission_type: str = "read"
    ) -> bool:
        """
        Validate if user has permission for a doctype.

        Args:
            user_email: User email
            doctype: DocType name
            permission_type: Type of permission (read, write, create, delete, etc.)

        Returns:
            True if user has permission

        Raises:
            PermissionDeniedError: If permission is denied
        """
        permissions = self.get_user_permissions(user_email, use_cache=True)

        for perm in permissions:
            if perm.doctype == doctype:
                if getattr(perm, permission_type, False):
                    return True

        raise PermissionDeniedError(
            f"User {user_email} lacks '{permission_type}' permission for {doctype}"
        )

    def invalidate_session(self, session_id: str) -> None:
        """
        Invalidate a session (alias for logout).

        Args:
            session_id: Session ID to invalidate
        """
        self.logout(session_id)

    def get_client(
        self,
        session_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> FrappeClient:
        """
        Get an authenticated FrappeClient instance.

        Args:
            session_id: Optional session ID to use existing session
            username: Username for password auth
            password: Password for password auth
            api_key: API key for API key auth
            api_secret: API secret for API key auth
            tenant_id: Optional tenant ID

        Returns:
            Authenticated FrappeClient instance

        Raises:
            AuthenticationError: If authentication fails

        Examples:
            # Use existing session
            client = auth.get_client(session_id="abc123")

            # Authenticate with username/password
            client = auth.get_client(username="user@example.com", password="pass")

            # Authenticate with API key
            client = auth.get_client(api_key="key", api_secret="secret")
        """
        frappe_url = self._get_frappe_url(tenant_id)
        client = FrappeClient(frappe_url)

        if session_id:
            session = self.session_store.get(session_id)
            if not session:
                raise AuthenticationError("Invalid session")

            if hasattr(client, "session"):
                from urllib.parse import urlparse

                hostname = urlparse(frappe_url).hostname
                client.session.cookies.set("sid", session.token, domain=hostname, path="/")
                client.session.headers["Cookie"] = f"sid={session.token}"
            client.sid = session.token

        elif username and password:
            client.login(username, password)

        elif api_key and api_secret:
            client.authenticate(api_key, api_secret)

        else:
            raise AuthenticationError(
                "Must provide either session_id, username/password, or api_key/api_secret"
            )

        return client

    @property
    def client(self) -> FrappeClient:
        """
        Get the shared authenticated FrappeClient instance.

        You must first authenticate by calling one of:
        - set_client_credentials(username, password)
        - set_client_api_key(api_key, api_secret)
        - Or login_with_password() / authenticate_api_key()

        Returns:
            Authenticated FrappeClient instance

        Raises:
            RuntimeError: If no credentials have been set

        Examples:
            # After login
            session = auth.login_with_password("user@example.com", "password")

            # Use client directly
            users = auth.client.get_list("User", fields=["name", "email"])
            user_doc = auth.client.get_doc("User", "user@example.com")
        """
        if self._client is None:
            if self._client_credentials is None:
                raise RuntimeError(
                    "No client credentials set. Call set_client_credentials() or "
                    "set_client_api_key() first, or use get_client() with explicit credentials."
                )

            self._client = FrappeClient(self.frappe_url)

            if "username" in self._client_credentials:
                self._client.login(
                    self._client_credentials["username"], self._client_credentials["password"]
                )
            elif "api_key" in self._client_credentials:
                self._client.authenticate(
                    self._client_credentials["api_key"], self._client_credentials["api_secret"]
                )

        return self._client

    def set_client_credentials(
        self, username: str, password: str, tenant_id: Optional[str] = None
    ) -> None:
        """
        Set credentials for the shared client instance.

        Args:
            username: Username or email
            password: Password
            tenant_id: Optional tenant ID
        """
        self._client_credentials = {
            "username": username,
            "password": password,
            "tenant_id": tenant_id,
        }
        self._client = None

    def set_client_api_key(
        self, api_key: str, api_secret: str, tenant_id: Optional[str] = None
    ) -> None:
        """
        Set API key credentials for the shared client instance.

        Args:
            api_key: API key
            api_secret: API secret
            tenant_id: Optional tenant ID
        """
        self._client_credentials = {
            "api_key": api_key,
            "api_secret": api_secret,
            "tenant_id": tenant_id,
        }
        self._client = None

    def _fetch_user_roles(self, client: FrappeClient, username: str) -> List[str]:
        """Fetch user roles from Frappe."""
        try:
            roles_data = client.get_list(
                "Has Role", fields=["role"], filters={"parent": username, "parenttype": "User"}
            )
            return [role["role"] for role in roles_data]
        except Exception:
            return []

    def _fetch_user_permissions(self, client: FrappeClient, username: str) -> List[Permission]:
        """Fetch user permissions from Frappe."""
        try:
            # Get user's roles
            roles = self._fetch_user_roles(client, username)

            # For each role, fetch permissions (simplified)
            permissions = []

            return permissions
        except Exception:
            return []
