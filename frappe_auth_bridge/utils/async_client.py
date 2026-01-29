"""Async HTTP client for Frappe API communication."""

import httpx
from typing import Any, Dict, Optional
from frappe_auth_bridge.exceptions import AuthenticationError


class AsyncFrappeClient:
    """Async HTTP client for communicating with Frappe API."""
    
    def __init__(self, base_url: str, timeout: int = 5, max_retries: int = 3,
                 verify_ssl: bool = True):
        """
        Initialize async Frappe client.
        
        Args:
            base_url: Base URL of Frappe server
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=True
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
    
    async def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None,
                  headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Make async GET request.
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            headers: Request headers
            
        Returns:
            Response JSON data
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use async context manager.")
        
        url = f"{self.base_url}{endpoint}"
        
        for attempt in range(self.max_retries):
            try:
                response = await self._client.get(url, params=params, headers=headers)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    raise AuthenticationError("Unauthorized request")
                if attempt == self.max_retries - 1:
                    raise
            except httpx.RequestError as e:
                if attempt == self.max_retries - 1:
                    raise AuthenticationError(f"Request failed: {str(e)}")
        
        raise AuthenticationError("Max retries exceeded")
    
    async def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None,
                   json_data: Optional[Dict[str, Any]] = None,
                   headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Make async POST request.
        
        Args:
            endpoint: API endpoint
            data: Form data
            json_data: JSON data
            headers: Request headers
            
        Returns:
            Response JSON data
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use async context manager.")
        
        url = f"{self.base_url}{endpoint}"
        
        for attempt in range(self.max_retries):
            try:
                response = await self._client.post(
                    url, data=data, json=json_data, headers=headers
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    raise AuthenticationError("Unauthorized request")
                if attempt == self.max_retries - 1:
                    raise
            except httpx.RequestError as e:
                if attempt == self.max_retries - 1:
                    raise AuthenticationError(f"Request failed: {str(e)}")
        
        raise AuthenticationError("Max retries exceeded")
