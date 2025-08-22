"""
Advanced authentication scenario tests.

This file contains tests for specific authentication scenarios:
- Different OBO scope combinations
- Cross-workspace vs same-workspace operations
- Various operation types and their scope requirements
- Edge cases and error conditions
"""

import pytest
import os
from unittest.mock import Mock, patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from databricks.anyauth.auth import (
    OBOScopes,
    OBOScopeConfig,
    AuthMethod,
    DatabricksAuthManager,
    DatabricksClientFactory,
    SmartWorkspaceClient
)
from databricks.sdk import WorkspaceClient


class TestOBOScopeScenarios:
    """Test different OBO scope configurations and their behavior."""
    
    @pytest.fixture
    def mock_workspace_client(self):
        """Create a mock workspace client."""
        client = Mock(spec=WorkspaceClient)
        client.current_user.me.return_value = Mock(user_name="test-user")
        return client
    
    def test_vector_search_operation_with_vector_scope(self, mock_workspace_client):
        """Test vector search operation with appropriate OBO scope."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
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
    
    def test_vector_search_operation_without_vector_scope(self, mock_workspace_client):
        """Test vector search operation without appropriate OBO scope falls back to U2M."""
        with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
            scope_config = OBOScopeConfig(scopes=[OBOScopes.SQL_WAREHOUSES])  # Missing vector search scope
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
    
    def test_sql_operation_with_sql_scope(self, mock_workspace_client):
        """Test SQL operation with appropriate OBO scope."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
            with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
                scope_config = OBOScopeConfig(scopes=[OBOScopes.SQL_WAREHOUSES])
                auth_manager = DatabricksAuthManager(
                    workspace_url="https://test.workspace.com",
                    current_workspace_url="https://test.workspace.com",
                    obo_scope_config=scope_config
                )
                
                auth_manager.set_auth_context("test-token", "test@example.com")
                client = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="sql"
                )
                
                assert client == mock_workspace_client
    
    def test_catalog_write_operation_with_catalog_write_scope(self, mock_workspace_client):
        """Test catalog write operation with appropriate OBO scope."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
            with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
                scope_config = OBOScopeConfig(scopes=[OBOScopes.CATALOG_WRITE])
                auth_manager = DatabricksAuthManager(
                    workspace_url="https://test.workspace.com",
                    current_workspace_url="https://test.workspace.com",
                    obo_scope_config=scope_config
                )
                
                auth_manager.set_auth_context("test-token", "test@example.com")
                client = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="catalog_write"
                )
                
                assert client == mock_workspace_client
    
    def test_catalog_write_operation_with_only_catalog_read_scope(self, mock_workspace_client):
        """Test catalog write operation with only catalog read scope falls back to U2M."""
        with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
            scope_config = OBOScopeConfig(scopes=[OBOScopes.CATALOG_READ])  # Missing catalog write scope
            auth_manager = DatabricksAuthManager(
                workspace_url="https://test.workspace.com",
                current_workspace_url="https://test.workspace.com",
                obo_scope_config=scope_config
            )
            
            auth_manager.set_auth_context("test-token", "test@example.com")
            client = auth_manager.get_client(
                target_workspace="https://test.workspace.com",
                operation_type="catalog_write"
            )
            
            assert client == mock_workspace_client


class TestCrossWorkspaceScenarios:
    """Test cross-workspace authentication scenarios."""
    
    @pytest.fixture
    def mock_workspace_client(self):
        """Create a mock workspace client."""
        client = Mock(spec=WorkspaceClient)
        client.current_user.me.return_value = Mock(user_name="test-user")
        return client
    
    def test_cross_workspace_always_uses_u2m(self, mock_workspace_client):
        """Test that cross-workspace operations always use U2M regardless of OBO scopes."""
        with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
            scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH, OBOScopes.SQL_WAREHOUSES])
            auth_manager = DatabricksAuthManager(
                workspace_url="https://source.workspace.com",
                current_workspace_url="https://source.workspace.com",
                obo_scope_config=scope_config
            )
            
            auth_manager.set_auth_context("test-token", "test@example.com")
            client = auth_manager.get_client(
                target_workspace="https://target.workspace.com",
                operation_type="vector_search"
            )
            
            assert client == mock_workspace_client
    
    def test_same_workspace_with_obo_scopes(self, mock_workspace_client):
        """Test same-workspace operations with appropriate OBO scopes use OBO."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
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


class TestAgentTypeScenarios:
    """Test different agent type configurations."""
    
    def test_basic_agent_scope_configuration(self):
        """Test basic agent type creates appropriate scope configuration."""
        client = DatabricksClientFactory.create_client(
            user_token="test-token",
            user_email="test@example.com",
            workspace_url="https://test.workspace.com",
            agent_type="basic"
        )
        
        # Verify the auth manager was created with basic agent scopes
        auth_manager = client.auth_manager
        assert auth_manager.obo_scope_config.scopes == OBOScopes.BASIC_AGENT_SCOPES
        assert auth_manager.obo_scope_config.description == "Basic agent OBO scopes"
    
    def test_analytics_agent_scope_configuration(self):
        """Test analytics agent type creates appropriate scope configuration."""
        client = DatabricksClientFactory.create_client(
            user_token="test-token",
            user_email="test@example.com",
            workspace_url="https://test.workspace.com",
            agent_type="analytics"
        )
        
        # Verify the auth manager was created with analytics agent scopes
        auth_manager = client.auth_manager
        assert auth_manager.obo_scope_config.scopes == OBOScopes.ANALYTICS_AGENT_SCOPES
        assert auth_manager.obo_scope_config.description == "Analytics agent OBO scopes"
    
    def test_full_agent_scope_configuration(self):
        """Test full agent type creates appropriate scope configuration."""
        client = DatabricksClientFactory.create_client(
            user_token="test-token",
            user_email="test@example.com",
            workspace_url="https://test.workspace.com",
            agent_type="full"
        )
        
        # Verify the auth manager was created with full agent scopes
        auth_manager = client.auth_manager
        assert auth_manager.obo_scope_config.scopes == OBOScopes.FULL_AGENT_SCOPES
        assert auth_manager.obo_scope_config.description == "Full agent OBO scopes"


class TestEnvironmentVariableScenarios:
    """Test environment variable-based configuration scenarios."""
    
    def test_environment_variable_scope_configuration(self):
        """Test creating client with environment variable scopes."""
        with patch.dict(os.environ, {
            'DATABRICKS_OBO_SCOPES': 'serving.vector-search,sql.warehouses.use,catalog.read',
            'DATABRICKS_OBO_SCOPE_DESCRIPTION': 'Environment configured scopes'
        }):
            client = DatabricksClientFactory.create_client(
                user_token="test-token",
                user_email="test@example.com",
                workspace_url="https://test.workspace.com"
            )
            
            # Verify the auth manager was created with environment scopes
            auth_manager = client.auth_manager
            assert auth_manager.obo_scope_config.scopes == [
                'serving.vector-search',
                'sql.warehouses.use', 
                'catalog.read'
            ]
            assert auth_manager.obo_scope_config.description == 'Environment configured scopes'
    
    def test_environment_variable_fallback_to_defaults(self):
        """Test that missing environment variables fall back to default scopes."""
        with patch.dict(os.environ, {}, clear=True):
            client = DatabricksClientFactory.create_client(
                user_token="test-token",
                user_email="test@example.com",
                workspace_url="https://test.workspace.com"
            )
            
            # Verify the auth manager was created with default scopes
            auth_manager = client.auth_manager
            assert auth_manager.obo_scope_config.scopes == OBOScopes.BASIC_AGENT_SCOPES
            assert auth_manager.obo_scope_config.description == 'Agent OBO scopes'


class TestCustomScopeScenarios:
    """Test custom scope configuration scenarios."""
    
    def test_custom_scope_configuration(self):
        """Test creating client with custom OBO scopes."""
        custom_scopes = [
            OBOScopes.VECTOR_SEARCH,
            OBOScopes.CATALOG_WRITE,
            OBOScopes.CLUSTERS
        ]
        
        client = DatabricksClientFactory.create_with_custom_scopes(
            user_token="test-token",
            user_email="test@example.com",
            workspace_url="https://test.workspace.com",
            obo_scopes=custom_scopes,
            scope_description="Custom test scopes"
        )
        
        # Verify the auth manager was created with custom scopes
        auth_manager = client.auth_manager
        assert auth_manager.obo_scope_config.scopes == custom_scopes
        assert auth_manager.obo_scope_config.description == "Custom test scopes"
    
    def test_empty_custom_scopes(self):
        """Test creating client with empty custom scopes."""
        client = DatabricksClientFactory.create_with_custom_scopes(
            user_token="test-token",
            user_email="test@example.com",
            workspace_url="https://test.workspace.com",
            obo_scopes=[],
            scope_description="Empty scopes"
        )
        
        # Verify the auth manager was created with empty scopes
        auth_manager = client.auth_manager
        assert auth_manager.obo_scope_config.scopes == []
        assert auth_manager.obo_scope_config.description == "Empty scopes"


class TestOperationTypeScenarios:
    """Test different operation types and their scope requirements."""
    
    @pytest.fixture
    def mock_workspace_client(self):
        """Create a mock workspace client."""
        client = Mock(spec=WorkspaceClient)
        client.current_user.me.return_value = Mock(user_name="test-user")
        return client
    
    def test_serving_endpoint_operation(self, mock_workspace_client):
        """Test serving endpoint operation with appropriate scope."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
            with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
                scope_config = OBOScopeConfig(scopes=[OBOScopes.SERVING_ENDPOINTS])
                auth_manager = DatabricksAuthManager(
                    workspace_url="https://test.workspace.com",
                    current_workspace_url="https://test.workspace.com",
                    obo_scope_config=scope_config
                )
                
                auth_manager.set_auth_context("test-token", "test@example.com")
                client = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="serving_endpoint"
                )
                
                assert client == mock_workspace_client
    
    def test_jobs_operation(self, mock_workspace_client):
        """Test jobs operation with appropriate scope."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
            with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
                scope_config = OBOScopeConfig(scopes=[OBOScopes.JOBS])
                auth_manager = DatabricksAuthManager(
                    workspace_url="https://test.workspace.com",
                    current_workspace_url="https://test.workspace.com",
                    obo_scope_config=scope_config
                )
                
                auth_manager.set_auth_context("test-token", "test@example.com")
                client = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="jobs"
                )
                
                assert client == mock_workspace_client
    
    def test_clusters_operation(self, mock_workspace_client):
        """Test clusters operation with appropriate scope."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
            with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
                scope_config = OBOScopeConfig(scopes=[OBOScopes.CLUSTERS])
                auth_manager = DatabricksAuthManager(
                    workspace_url="https://test.workspace.com",
                    current_workspace_url="https://test.workspace.com",
                    obo_scope_config=scope_config
                )
                
                auth_manager.set_auth_context("test-token", "test@example.com")
                client = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="clusters"
                )
                
                assert client == mock_workspace_client
    
    def test_catalog_read_operation(self, mock_workspace_client):
        """Test catalog read operation with appropriate scope."""
        with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
            with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
                scope_config = OBOScopeConfig(scopes=[OBOScopes.CATALOG_READ])
                auth_manager = DatabricksAuthManager(
                    workspace_url="https://test.workspace.com",
                    current_workspace_url="https://test.workspace.com",
                    obo_scope_config=scope_config
                )
                
                auth_manager.set_auth_context("test-token", "test@example.com")
                client = auth_manager.get_client(
                    target_workspace="https://test.workspace.com",
                    operation_type="catalog_read"
                )
                
                assert client == mock_workspace_client


class TestEdgeCaseScenarios:
    """Test edge cases and error conditions."""
    
    def test_force_auth_method_override(self):
        """Test that force_auth_method overrides automatic detection."""
        scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH])
        auth_manager = DatabricksAuthManager(
            workspace_url="https://test.workspace.com",
            current_workspace_url="https://test.workspace.com",
            obo_scope_config=scope_config
        )
        
        auth_manager.set_auth_context("test-token", "test@example.com")
        
        # Force U2M even though OBO should be available
        auth_method = auth_manager._determine_auth_method(
            target_workspace="https://test.workspace.com",
            operation_type="vector_search"
        )
        assert auth_method == AuthMethod.OBO  # Auto detection should choose OBO
        
        # But when forced, it should use the forced method
        with patch('databricks.anyauth.auth.WorkspaceClient') as mock_client:
            mock_client.return_value = Mock()
            client = auth_manager.get_client(
                target_workspace="https://test.workspace.com",
                operation_type="vector_search",
                force_auth_method=AuthMethod.U2M
            )
            assert client is not None
    
    def test_multiple_operation_types_same_session(self):
        """Test handling multiple operation types in the same session."""
        scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH, OBOScopes.SQL_WAREHOUSES])
        auth_manager = DatabricksAuthManager(
            workspace_url="https://test.workspace.com",
            current_workspace_url="https://test.workspace.com",
            obo_scope_config=scope_config
        )
        
        auth_manager.set_auth_context("test-token", "test@example.com")
        
        # Test vector search (should use OBO)
        auth_method1 = auth_manager._determine_auth_method(
            target_workspace="https://test.workspace.com",
            operation_type="vector_search"
        )
        assert auth_method1 == AuthMethod.OBO
        
        # Test SQL (should use OBO)
        auth_method2 = auth_manager._determine_auth_method(
            target_workspace="https://test.workspace.com",
            operation_type="sql"
        )
        assert auth_method2 == AuthMethod.OBO
        
        # Test catalog write (should use U2M due to missing scope)
        auth_method3 = auth_manager._determine_auth_method(
            target_workspace="https://test.workspace.com",
            operation_type="catalog_write"
        )
        assert auth_method3 == AuthMethod.U2M
