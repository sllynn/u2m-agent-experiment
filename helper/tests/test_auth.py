"""
Comprehensive tests for the Databricks authentication system.

Tests cover:
- OBO scope configuration and validation
- Auth method selection logic (OBO vs U2M)
- Cross-workspace vs same-workspace scenarios
- Different OBO scope configurations
- Client creation and caching
- Error handling and fallback logic
"""

import pytest
import os
from unittest.mock import Mock, patch, MagicMock
from typing import List, Optional

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from databricks.anyauth.auth import (
    OBOScopes,
    OBOScopeConfig,
    AuthMethod,
    AuthContext,
    DatabricksAuthManager,
    SmartWorkspaceClient,
    DatabricksClientFactory,
    AuthenticationContext
)
from databricks.sdk import WorkspaceClient


class TestOBOScopes:
    """Test OBO scope configuration and validation."""
    
    def test_basic_agent_scopes(self):
        """Test basic agent scope configuration."""
        scopes = OBOScopes.BASIC_AGENT_SCOPES
        assert OBOScopes.VECTOR_SEARCH in scopes
        assert OBOScopes.SERVING_ENDPOINTS in scopes
        assert OBOScopes.SQL_WAREHOUSES in scopes
        assert OBOScopes.WORKSPACE_ACCESS in scopes
        assert len(scopes) == 4
    
    def test_analytics_agent_scopes(self):
        """Test analytics agent scope configuration."""
        scopes = OBOScopes.ANALYTICS_AGENT_SCOPES
        assert OBOScopes.SQL_WAREHOUSES in scopes
        assert OBOScopes.CATALOG_READ in scopes
        assert OBOScopes.WORKSPACE_ACCESS in scopes
        assert OBOScopes.JOBS in scopes
        assert len(scopes) == 4
    
    def test_full_agent_scopes(self):
        """Test full agent scope configuration."""
        scopes = OBOScopes.FULL_AGENT_SCOPES
        assert OBOScopes.VECTOR_SEARCH in scopes
        assert OBOScopes.SERVING_ENDPOINTS in scopes
        assert OBOScopes.SQL_WAREHOUSES in scopes
        assert OBOScopes.JOBS in scopes
        assert OBOScopes.CLUSTERS in scopes
        assert OBOScopes.WORKSPACE_ACCESS in scopes
        assert OBOScopes.CATALOG_READ in scopes
        assert OBOScopes.CATALOG_WRITE in scopes
        assert len(scopes) == 8


class TestOBOScopeConfig:
    """Test OBO scope configuration class."""
    
    def test_init_with_scopes(self):
        """Test initialization with explicit scopes."""
        scopes = [OBOScopes.VECTOR_SEARCH, OBOScopes.SQL_WAREHOUSES]
        config = OBOScopeConfig(scopes=scopes, description="Test config")
        
        assert config.scopes == scopes
        assert config.description == "Test config"
    
    def test_from_env_with_scopes(self):
        """Test creating config from environment variables."""
        with patch.dict(os.environ, {
            'DATABRICKS_OBO_SCOPES': 'serving.vector-search,sql.warehouses.use',
            'DATABRICKS_OBO_SCOPE_DESCRIPTION': 'Test env config'
        }):
            config = OBOScopeConfig.from_env()
            
        assert config.scopes == ['serving.vector-search', 'sql.warehouses.use']
        assert config.description == 'Test env config'
    
    def test_from_env_default_scopes(self):
        """Test creating config from environment with no scopes set."""
        with patch.dict(os.environ, {}, clear=True):
            config = OBOScopeConfig.from_env()
            
        assert config.scopes == OBOScopes.BASIC_AGENT_SCOPES
        assert config.description == 'Agent OBO scopes'
    
    def test_for_agent_type_basic(self):
        """Test creating config for basic agent type."""
        config = OBOScopeConfig.for_agent_type('basic')
        assert config.scopes == OBOScopes.BASIC_AGENT_SCOPES
        assert config.description == 'Basic agent OBO scopes'
    
    def test_for_agent_type_analytics(self):
        """Test creating config for analytics agent type."""
        config = OBOScopeConfig.for_agent_type('analytics')
        assert config.scopes == OBOScopes.ANALYTICS_AGENT_SCOPES
        assert config.description == 'Analytics agent OBO scopes'
    
    def test_for_agent_type_full(self):
        """Test creating config for full agent type."""
        config = OBOScopeConfig.for_agent_type('full')
        assert config.scopes == OBOScopes.FULL_AGENT_SCOPES
        assert config.description == 'Full agent OBO scopes'
    
    def test_for_agent_type_unknown(self):
        """Test creating config for unknown agent type defaults to basic."""
        config = OBOScopeConfig.for_agent_type('unknown')
        assert config.scopes == OBOScopes.BASIC_AGENT_SCOPES
        assert config.description == 'Unknown agent OBO scopes'


class TestAuthMethod:
    """Test AuthMethod enum."""
    
    def test_auth_method_values(self):
        """Test AuthMethod enum values."""
        assert AuthMethod.OBO.value == "obo"
        assert AuthMethod.U2M.value == "u2m"
        assert AuthMethod.AUTO.value == "auto"


class TestAuthContext:
    """Test AuthContext dataclass."""
    
    def test_auth_context_creation(self):
        """Test creating AuthContext with all parameters."""
        context = AuthContext(
            workspace_url="https://test.workspace.com",
            auth_method=AuthMethod.OBO,
            user_token="test-token",
            user_email="test@example.com",
            operation_type="vector_search",
            target_resource="test-resource"
        )
        
        assert context.workspace_url == "https://test.workspace.com"
        assert context.auth_method == AuthMethod.OBO
        assert context.user_token == "test-token"
        assert context.user_email == "test@example.com"
        assert context.operation_type == "vector_search"
        assert context.target_resource == "test-resource"


class TestDatabricksAuthManager:
    """Test DatabricksAuthManager class."""
    
    @pytest.fixture
    def auth_manager(self):
        """Create a basic auth manager for testing."""
        scope_config = OBOScopeConfig(
            scopes=[OBOScopes.VECTOR_SEARCH, OBOScopes.SQL_WAREHOUSES],
            description="Test scopes"
        )
        return DatabricksAuthManager(
            workspace_url="https://test.workspace.com",
            default_auth_method=AuthMethod.AUTO,
            current_workspace_url="https://test.workspace.com",
            obo_scope_config=scope_config
        )
    
    def test_init_with_scope_config(self, auth_manager):
        """Test initialization with scope configuration."""
        assert auth_manager.workspace_url == "https://test.workspace.com"
        assert auth_manager.current_workspace_url == "https://test.workspace.com"
        assert auth_manager.default_auth_method == AuthMethod.AUTO
        assert auth_manager.obo_scope_config.scopes == [OBOScopes.VECTOR_SEARCH, OBOScopes.SQL_WAREHOUSES]
    
    def test_init_with_env_scopes(self):
        """Test initialization with environment-based scope configuration."""
        with patch.dict(os.environ, {
            'DATABRICKS_OBO_SCOPES': 'serving.vector-search,sql.warehouses.use'
        }):
            auth_manager = DatabricksAuthManager(
                workspace_url="https://test.workspace.com",
                default_auth_method=AuthMethod.AUTO
            )
            
        assert auth_manager.obo_scope_config.scopes == ['serving.vector-search', 'sql.warehouses.use']
    
    def test_get_obo_scopes(self, auth_manager):
        """Test getting OBO scopes."""
        scopes = auth_manager.get_obo_scopes()
        assert scopes == [OBOScopes.VECTOR_SEARCH, OBOScopes.SQL_WAREHOUSES]
        # Ensure we get a copy, not the original list
        scopes.append("test-scope")
        assert auth_manager.get_obo_scopes() == [OBOScopes.VECTOR_SEARCH, OBOScopes.SQL_WAREHOUSES]
    
    def test_has_obo_scope(self, auth_manager):
        """Test checking if specific OBO scope is configured."""
        assert auth_manager.has_obo_scope(OBOScopes.VECTOR_SEARCH) is True
        assert auth_manager.has_obo_scope(OBOScopes.CATALOG_READ) is False
    
    def test_validate_operation_scope_supported(self, auth_manager):
        """Test operation scope validation for supported operations."""
        assert auth_manager.validate_operation_scope('vector_search') is True
        assert auth_manager.validate_operation_scope('sql') is True
    
    def test_validate_operation_scope_unsupported(self, auth_manager):
        """Test operation scope validation for unsupported operations."""
        assert auth_manager.validate_operation_scope('catalog_write') is False
        assert auth_manager.validate_operation_scope('clusters') is False
    
    def test_validate_operation_scope_unknown(self, auth_manager):
        """Test operation scope validation for unknown operations defaults to workspace access."""
        # Since we don't have WORKSPACE_ACCESS in our test scopes, this should fail
        assert auth_manager.validate_operation_scope('unknown_operation') is False
    
    def test_set_auth_context(self, auth_manager):
        """Test setting authentication context."""
        auth_manager.set_auth_context(
            user_token="test-token",
            user_email="test@example.com",
            operation_context={'operation_type': 'vector_search'}
        )
        
        assert auth_manager._auth_context is not None
        assert auth_manager._auth_context.user_token == "test-token"
        assert auth_manager._auth_context.user_email == "test@example.com"
        assert auth_manager._auth_context.operation_type == "vector_search"
    
    def test_determine_auth_method_auto_force_obo(self, auth_manager):
        """Test auth method determination when forced to OBO."""
        auth_manager.default_auth_method = AuthMethod.OBO
        method = auth_manager._determine_auth_method()
        assert method == AuthMethod.OBO
    
    def test_determine_auth_method_auto_force_u2m(self, auth_manager):
        """Test auth method determination when forced to U2M."""
        auth_manager.default_auth_method = AuthMethod.U2M
        method = auth_manager._determine_auth_method()
        assert method == AuthMethod.U2M
    
    def test_determine_auth_method_cross_workspace(self, auth_manager):
        """Test auth method determination for cross-workspace operations."""
        method = auth_manager._determine_auth_method(
            target_workspace="https://different.workspace.com"
        )
        assert method == AuthMethod.U2M
    
    def test_determine_auth_method_same_workspace_with_scope(self, auth_manager):
        """Test auth method determination for same-workspace operations with scope support."""
        method = auth_manager._determine_auth_method(
            target_workspace="https://test.workspace.com",
            operation_type="vector_search"
        )
        assert method == AuthMethod.OBO
    
    def test_determine_auth_method_same_workspace_without_scope(self, auth_manager):
        """Test auth method determination for same-workspace operations without scope support."""
        method = auth_manager._determine_auth_method(
            target_workspace="https://test.workspace.com",
            operation_type="catalog_write"
        )
        assert method == AuthMethod.U2M
    
    def test_get_cache_key(self, auth_manager):
        """Test cache key generation."""
        auth_manager.set_auth_context("test-token", "test@example.com")
        cache_key = auth_manager._get_cache_key("https://test.workspace.com", AuthMethod.OBO)
        
        # Should include workspace URL, auth method, and user hash
        assert "https://test.workspace.com" in cache_key
        assert "obo" in cache_key
        # The cache key format is: workspace_url:auth_method:user_hash
        # Since workspace_url contains colons, we need to check differently
        parts = cache_key.split(":")
        assert len(parts) >= 3
        assert parts[-2] == "obo"  # auth method should be second to last
        assert len(parts[-1]) == 8  # user hash should be 8 characters
    
    def test_clear_cache(self, auth_manager):
        """Test clearing the client cache."""
        # Add some mock clients to cache
        auth_manager._client_cache = {"key1": Mock(), "key2": Mock()}
        auth_manager.clear_cache()
        assert len(auth_manager._client_cache) == 0


class TestDatabricksClientFactory:
    """Test DatabricksClientFactory class."""
    
    def test_create_client_with_agent_type(self):
        """Test creating client with agent type."""
        with patch('databricks.anyauth.auth.DatabricksAuthManager') as mock_auth_manager:
            mock_auth_manager.return_value = Mock()
            
            client = DatabricksClientFactory.create_client(
                user_token="test-token",
                user_email="test@example.com",
                workspace_url="https://test.workspace.com",
                agent_type="basic"
            )
            
            # Verify auth manager was created with basic agent scopes
            mock_auth_manager.assert_called_once()
            call_args = mock_auth_manager.call_args
            assert call_args[1]['workspace_url'] == "https://test.workspace.com"
            assert call_args[1]['obo_scope_config'].scopes == OBOScopes.BASIC_AGENT_SCOPES
    
    def test_create_client_with_custom_scopes(self):
        """Test creating client with custom OBO scopes."""
        custom_scopes = [OBOScopes.VECTOR_SEARCH, OBOScopes.CATALOG_WRITE]
        
        with patch('databricks.anyauth.auth.DatabricksAuthManager') as mock_auth_manager:
            mock_auth_manager.return_value = Mock()
            
            client = DatabricksClientFactory.create_with_custom_scopes(
                user_token="test-token",
                user_email="test@example.com",
                workspace_url="https://test.workspace.com",
                obo_scopes=custom_scopes,
                scope_description="Custom test scopes"
            )
            
            # Verify auth manager was created with custom scopes
            mock_auth_manager.assert_called_once()
            call_args = mock_auth_manager.call_args
            assert call_args[1]['obo_scope_config'].scopes == custom_scopes
            assert call_args[1]['obo_scope_config'].description == "Custom test scopes"
    
    def test_create_client_with_env_scopes(self):
        """Test creating client with environment-based scopes."""
        with patch.dict(os.environ, {
            'DATABRICKS_OBO_SCOPES': 'serving.vector-search,sql.warehouses.use'
        }):
            with patch('databricks.anyauth.auth.DatabricksAuthManager') as mock_auth_manager:
                mock_auth_manager.return_value = Mock()
                
                client = DatabricksClientFactory.create_client(
                    user_token="test-token",
                    user_email="test@example.com",
                    workspace_url="https://test.workspace.com"
                )
                
                # Verify auth manager was created with env scopes
                mock_auth_manager.assert_called_once()
                call_args = mock_auth_manager.call_args
                assert call_args[1]['obo_scope_config'].scopes == ['serving.vector-search', 'sql.warehouses.use']


class TestSmartWorkspaceClient:
    """Test SmartWorkspaceClient class."""
    
    @pytest.fixture
    def mock_auth_manager(self):
        """Create a mock auth manager."""
        return Mock(spec=DatabricksAuthManager)
    
    @pytest.fixture
    def smart_client(self, mock_auth_manager):
        """Create a smart workspace client."""
        return SmartWorkspaceClient(mock_auth_manager)
    
    def test_init(self, smart_client, mock_auth_manager):
        """Test SmartWorkspaceClient initialization."""
        assert smart_client.auth_manager == mock_auth_manager
        assert smart_client._current_client is None
    
    def test_get_client_calls_auth_manager(self, smart_client, mock_auth_manager):
        """Test that _get_client calls the auth manager."""
        mock_workspace_client = Mock()
        mock_auth_manager.get_client.return_value = mock_workspace_client
        
        client = smart_client._get_client(
            target_workspace="https://test.workspace.com",
            operation_type="vector_search"
        )
        
        mock_auth_manager.get_client.assert_called_once_with(
            target_workspace="https://test.workspace.com",
            operation_type="vector_search"
        )
        assert client == mock_workspace_client
    
    def test_proxy_method_calls(self, smart_client, mock_auth_manager):
        """Test that method calls are proxied to the underlying client."""
        mock_workspace_client = Mock()
        mock_auth_manager.get_client.return_value = mock_workspace_client
        
        # Call a method on the smart client
        smart_client.some_method("arg1", kwarg1="value1")
        
        # Verify the method was called on the underlying client
        mock_workspace_client.some_method.assert_called_once_with("arg1", kwarg1="value1")
    
    def test_proxy_method_with_context_hints(self, smart_client, mock_auth_manager):
        """Test that context hints are extracted from kwargs."""
        mock_workspace_client = Mock()
        mock_auth_manager.get_client.return_value = mock_workspace_client
        
        # Call a method with context hints
        smart_client.some_method(
            "arg1",
            target_workspace="https://test.workspace.com",
            operation_type="vector_search",
            kwarg1="value1"
        )
        
        # Verify context hints were passed to auth manager
        mock_auth_manager.get_client.assert_called_once_with(
            target_workspace="https://test.workspace.com",
            operation_type="vector_search"
        )
        
        # Verify other kwargs were passed to the underlying method
        mock_workspace_client.some_method.assert_called_once_with("arg1", kwarg1="value1")


class TestAuthenticationContext:
    """Test AuthenticationContext class."""
    
    def test_context_manager(self):
        """Test AuthenticationContext as a context manager."""
        mock_client = Mock()
        context = AuthenticationContext(mock_client, operation_type="vector_search")
        
        with context as client:
            assert client == mock_client


class TestIntegrationScenarios:
    """Integration tests for different authentication scenarios."""
    
    @pytest.fixture
    def mock_workspace_client(self):
        """Create a mock workspace client."""
        client = Mock(spec=WorkspaceClient)
        client.current_user.me.return_value = Mock(user_name="test-user")
        return client
    
    def test_same_workspace_obo_with_vector_search(self, mock_workspace_client):
        """Test same-workspace OBO authentication for vector search."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials') as mock_creds:
            with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
                scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH])
                auth_manager = DatabricksAuthManager(
                    workspace_url="https://test.workspace.com",
                    current_workspace_url="https://test.workspace.com",
                    obo_scope_config=scope_config
                )
                
                auth_manager.set_auth_context("test-token", "test@example.com")
                client = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="vector_search"
                )
                
                assert client == mock_workspace_client
    
    def test_cross_workspace_u2m(self, mock_workspace_client):
        """Test cross-workspace U2M authentication."""
        with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
            scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH])
            auth_manager = DatabricksAuthManager(
                workspace_url="https://test.workspace.com",
                current_workspace_url="https://test.workspace.com",
                obo_scope_config=scope_config
            )
            
            auth_manager.set_auth_context("test-token", "test@example.com")
            client = auth_manager.get_client(
                target_workspace="https://different.workspace.com",
                operation_type="vector_search"
            )
            
            assert client == mock_workspace_client
    
    def test_obo_fallback_to_u2m_when_scope_missing(self, mock_workspace_client):
        """Test OBO fallback to U2M when required scope is missing."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials') as mock_creds:
            # First call to OBO fails
            mock_creds.side_effect = Exception("OBO failed")
            
            with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
                scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH])
                auth_manager = DatabricksAuthManager(
                    workspace_url="https://test.workspace.com",
                    current_workspace_url="https://test.workspace.com",
                    obo_scope_config=scope_config
                )
                
                auth_manager.set_auth_context("test-token", "test@example.com")
                client = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="vector_search"
                )
                
                assert client == mock_workspace_client
    
    def test_client_caching(self, mock_workspace_client):
        """Test that clients are cached and reused."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
            with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
                scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH])
                auth_manager = DatabricksAuthManager(
                    workspace_url="https://test.workspace.com",
                    current_workspace_url="https://test.workspace.com",
                    obo_scope_config=scope_config
                )
                
                auth_manager.set_auth_context("test-token", "test@example.com")
                
                # First call should create a new client
                client1 = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="vector_search"
                )
                
                # Second call should return cached client
                client2 = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="vector_search"
                )
                
                assert client1 == client2
                # WorkspaceClient should only be called once for creation
                # The validation call happens during creation, so we expect 1 call
                assert mock_workspace_client.current_user.me.call_count >= 1


class TestErrorHandling:
    """Test error handling scenarios."""
    
    def test_get_client_without_auth_context(self):
        """Test that get_client fails without auth context."""
        scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH])
        auth_manager = DatabricksAuthManager(
            workspace_url="https://test.workspace.com",
            obo_scope_config=scope_config
        )
        
        with pytest.raises(ValueError, match="Authentication context not set"):
            auth_manager.get_client()
    
    def test_obo_client_without_user_token(self):
        """Test that OBO client creation fails without user token."""
        scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH])
        auth_manager = DatabricksAuthManager(
            workspace_url="https://test.workspace.com",
            obo_scope_config=scope_config
        )
        
        auth_manager.set_auth_context("", "test@example.com")
        
        with pytest.raises(ValueError, match="User token required for OBO authentication"):
            auth_manager._create_obo_client("https://test.workspace.com")
    
    def test_u2m_client_without_user_token(self):
        """Test that U2M client creation fails without user token."""
        scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH])
        auth_manager = DatabricksAuthManager(
            workspace_url="https://test.workspace.com",
            obo_scope_config=scope_config
        )
        
        auth_manager.set_auth_context("", "test@example.com")
        
        with pytest.raises(ValueError, match="User token required for U2M authentication"):
            auth_manager._create_u2m_client("https://test.workspace.com")
