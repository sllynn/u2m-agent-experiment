"""
Tests for the AnyAuth class.
"""

import pytest
from databricks.anyauth import AnyAuth


class TestAnyAuth:
    """Test cases for the AnyAuth class."""
    
    def test_init_with_token(self):
        """Test initialization with token."""
        auth = AnyAuth(token="test-token")
        assert auth.token == "test-token"
        assert auth.username is None
        assert auth.password is None
    
    def test_init_with_credentials(self):
        """Test initialization with username and password."""
        auth = AnyAuth(username="test-user", password="test-pass")
        assert auth.username == "test-user"
        assert auth.password == "test-pass"
        assert auth.token is None
    
    def test_get_auth_headers_with_token(self):
        """Test getting auth headers with token."""
        auth = AnyAuth(token="test-token")
        headers = auth.get_auth_headers()
        assert headers["Authorization"] == "Bearer test-token"
    
    def test_get_auth_headers_with_credentials(self):
        """Test getting auth headers with username/password."""
        auth = AnyAuth(username="test-user", password="test-pass")
        headers = auth.get_auth_headers()
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")
    
    def test_get_auth_headers_no_auth(self):
        """Test getting auth headers with no authentication."""
        auth = AnyAuth()
        headers = auth.get_auth_headers()
        assert headers == {}
    
    def test_repr_with_token(self):
        """Test string representation with token auth."""
        auth = AnyAuth(token="test-token")
        assert repr(auth) == "AnyAuth(auth_type='token')"
    
    def test_repr_with_credentials(self):
        """Test string representation with basic auth."""
        auth = AnyAuth(username="test-user", password="test-pass")
        assert repr(auth) == "AnyAuth(auth_type='basic')"
    
    def test_repr_no_auth(self):
        """Test string representation with no auth."""
        auth = AnyAuth()
        assert repr(auth) == "AnyAuth(auth_type='none')"
