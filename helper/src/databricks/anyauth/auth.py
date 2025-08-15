"""
Databricks Authentication Manager - Drop-in replacement for existing Databricks SDK clients
Provides runtime switching between OBO and U2M authentication with minimal changes to existing code
Handles OBO scope management for agent deployments
"""

import os
import hashlib
from typing import Optional, Dict, Any, Union, List
from enum import Enum
from dataclasses import dataclass
from threading import Lock
import logging

from databricks.sdk import WorkspaceClient
from databricks.sdk.oauth import Token
from databricks_ai_bridge import ModelServingUserCredentials

logger = logging.getLogger(__name__)

# OBO Scope Configuration
class OBOScopes:
    """
    Configuration class for OBO authentication scopes
    These are typically set at agent deployment time and don't change per session
    """
    
    # Standard OBO scopes for common operations
    VECTOR_SEARCH = "serving.vector-search"
    SERVING_ENDPOINTS = "serving.serving-endpoints" 
    SQL_WAREHOUSES = "sql.warehouses.use"
    JOBS = "jobs.view"
    CLUSTERS = "clusters.use"
    WORKSPACE_ACCESS = "workspace.workspace.use"
    CATALOG_READ = "catalog.read"
    CATALOG_WRITE = "catalog.write"
    
    # Predefined scope sets for common agent patterns
    BASIC_AGENT_SCOPES = [
        VECTOR_SEARCH,
        SERVING_ENDPOINTS,
        SQL_WAREHOUSES,
        WORKSPACE_ACCESS
    ]
    
    ANALYTICS_AGENT_SCOPES = [
        SQL_WAREHOUSES,
        CATALOG_READ,
        WORKSPACE_ACCESS,
        JOBS
    ]
    
    FULL_AGENT_SCOPES = [
        VECTOR_SEARCH,
        SERVING_ENDPOINTS,
        SQL_WAREHOUSES,
        JOBS,
        CLUSTERS,
        WORKSPACE_ACCESS,
        CATALOG_READ,
        CATALOG_WRITE
    ]

@dataclass
class OBOScopeConfig:
    """
    OBO scope configuration for the agent
    Set once at initialization, used for all OBO operations
    """
    scopes: List[str]
    description: str = "Agent OBO scopes"
    
    @classmethod
    def from_env(cls) -> 'OBOScopeConfig':
        """Create scope config from environment variables"""
        scopes_str = os.getenv('DATABRICKS_OBO_SCOPES', '')
        if scopes_str:
            scopes = [scope.strip() for scope in scopes_str.split(',')]
        else:
            # Default to basic agent scopes
            scopes = OBOScopes.BASIC_AGENT_SCOPES.copy()
            
        return cls(
            scopes=scopes,
            description=os.getenv('DATABRICKS_OBO_SCOPE_DESCRIPTION', 'Agent OBO scopes')
        )
    
    @classmethod
    def for_agent_type(cls, agent_type: str) -> 'OBOScopeConfig':
        """Create scope config for specific agent types"""
        scope_mapping = {
            'basic': OBOScopes.BASIC_AGENT_SCOPES,
            'analytics': OBOScopes.ANALYTICS_AGENT_SCOPES,
            'full': OBOScopes.FULL_AGENT_SCOPES
        }
        
        scopes = scope_mapping.get(agent_type.lower(), OBOScopes.BASIC_AGENT_SCOPES)
        return cls(
            scopes=scopes.copy(),
            description=f"{agent_type.title()} agent OBO scopes"
        )

class AuthMethod(Enum):
    OBO = "obo"  # On-Behalf-Of
    U2M = "u2m"  # User-to-Machine
    AUTO = "auto"  # Automatic detection

@dataclass
class AuthContext:
    """Authentication context for a specific operation"""
    workspace_url: str
    auth_method: AuthMethod
    user_token: Optional[str] = None
    user_email: Optional[str] = None
    operation_type: Optional[str] = None
    target_resource: Optional[str] = None

class DatabricksAuthManager:
    """
    Authentication manager that provides runtime switching between OBO and U2M
    Drop-in replacement for WorkspaceClient with intelligent auth method selection
    Handles OBO scope configuration at initialization
    """
    
    def __init__(self, 
                 workspace_url: str,
                 default_auth_method: AuthMethod = AuthMethod.AUTO,
                 current_workspace_url: Optional[str] = None,
                 obo_scope_config: Optional[OBOScopeConfig] = None):
        """
        Initialize the authentication manager
        
        Args:
            workspace_url: Primary workspace URL
            default_auth_method: Default authentication method
            current_workspace_url: URL of the current/local workspace (for cross-workspace detection)
            obo_scope_config: OBO scope configuration (set once at initialization)
        """
        self.workspace_url = workspace_url
        self.current_workspace_url = current_workspace_url or workspace_url
        self.default_auth_method = default_auth_method
        
        # OBO scope configuration - set once, used for all OBO operations
        self.obo_scope_config = obo_scope_config or OBOScopeConfig.from_env()
        
        # Log OBO scope configuration for debugging
        logger.info(f"OBO scopes configured: {self.obo_scope_config.scopes}")
        
        # Client cache for performance
        self._client_cache: Dict[str, WorkspaceClient] = {}
        self._cache_lock = Lock()
        
        # Authentication context
        self._auth_context: Optional[AuthContext] = None
        
        # Validate OBO scope configuration at startup
        self._validate_obo_scopes()
    
    def _validate_obo_scopes(self):
        """
        Validate OBO scope configuration
        This helps catch configuration issues early
        """
        if not self.obo_scope_config.scopes:
            logger.warning("No OBO scopes configured. OBO authentication may fail.")
            return
            
        # Check for common scope patterns
        has_basic_scopes = any(scope in self.obo_scope_config.scopes 
                             for scope in [OBOScopes.WORKSPACE_ACCESS])
        
        if not has_basic_scopes:
            logger.warning("No basic workspace access scopes found. Some operations may fail.")
            
        logger.info(f"OBO scope validation passed. Configured scopes: {len(self.obo_scope_config.scopes)}")
    
    def get_obo_scopes(self) -> List[str]:
        """Get configured OBO scopes"""
        return self.obo_scope_config.scopes.copy()
    
    def has_obo_scope(self, scope: str) -> bool:
        """Check if specific OBO scope is configured"""
        return scope in self.obo_scope_config.scopes
    
    def validate_operation_scope(self, operation_type: str) -> bool:
        """
        Validate if current OBO scopes support the requested operation
        
        Args:
            operation_type: Type of operation (e.g., 'vector_search', 'sql', 'serving')
            
        Returns:
            True if operation is supported by current OBO scopes
        """
        scope_requirements = {
            'vector_search': [OBOScopes.VECTOR_SEARCH],
            'serving_endpoint': [OBOScopes.SERVING_ENDPOINTS],
            'sql': [OBOScopes.SQL_WAREHOUSES],
            'jobs': [OBOScopes.JOBS],
            'clusters': [OBOScopes.CLUSTERS],
            'catalog_read': [OBOScopes.CATALOG_READ],
            'catalog_write': [OBOScopes.CATALOG_WRITE]
        }
        
        required_scopes = scope_requirements.get(operation_type, [])
        if not required_scopes:
            # Unknown operation type - assume it needs basic workspace access
            required_scopes = [OBOScopes.WORKSPACE_ACCESS]
            
        return any(scope in self.obo_scope_config.scopes for scope in required_scopes)
        
    def set_auth_context(self, user_token: str, user_email: str, operation_context: Dict[str, Any] = None):
        """
        Set authentication context for subsequent operations
        This is the main integration point with existing agent code
        """
        self._auth_context = AuthContext(
            workspace_url=self.workspace_url,
            auth_method=self.default_auth_method,
            user_token=user_token,
            user_email=user_email,
            operation_type=operation_context.get('operation_type') if operation_context else None,
            target_resource=operation_context.get('target_resource') if operation_context else None
        )
    
    def _determine_auth_method(self, target_workspace: Optional[str] = None, 
                              operation_type: Optional[str] = None) -> AuthMethod:
        """
        Intelligently determine authentication method based on operation context and scope availability
        """
        if self.default_auth_method != AuthMethod.AUTO:
            return self.default_auth_method
            
        # Cross-workspace operations always need U2M
        if target_workspace and target_workspace != self.current_workspace_url:
            logger.info(f"Cross-workspace operation detected: {target_workspace}. Using U2M auth.")
            return AuthMethod.U2M
        
        # For same-workspace operations, check if OBO scopes support the operation
        if operation_type and not self.validate_operation_scope(operation_type):
            logger.warning(f"Operation '{operation_type}' not supported by OBO scopes. Falling back to U2M.")
            return AuthMethod.U2M
            
        # Same workspace operations with appropriate scopes - prefer OBO for security
        logger.info(f"Same-workspace operation detected with OBO scope support. Using OBO auth.")
        return AuthMethod.OBO
    
    def _create_obo_client(self, workspace_url: str) -> WorkspaceClient:
        """Create OBO authenticated client with configured scopes"""
        if not self._auth_context or not self._auth_context.user_token:
            raise ValueError("User token required for OBO authentication")
            
        try:
            # Use Databricks AI Bridge for OBO authentication with configured scopes
            credentials = ModelServingUserCredentials()
            
            # The scopes are configured at the serving endpoint level, not client level
            # But we log them here for debugging
            logger.debug(f"Creating OBO client with scopes: {self.obo_scope_config.scopes}")
            
            client = WorkspaceClient(
                host=workspace_url,
                credentials_strategy=credentials
            )
            
            # Validate client can perform basic operations with configured scopes
            try:
                # Test basic workspace access
                user_info = client.current_user.me()
                logger.info(f"OBO client created successfully for user: {user_info.user_name}")
            except Exception as e:
                logger.warning(f"OBO client created but basic validation failed: {e}")
                
            logger.info(f"Created OBO client for workspace: {workspace_url}")
            return client
            
        except Exception as e:
            logger.error(f"Failed to create OBO client: {e}")
            # Log scope configuration for debugging
            logger.error(f"Configured OBO scopes: {self.obo_scope_config.scopes}")
            raise
    
    def _create_u2m_client(self, workspace_url: str) -> WorkspaceClient:
        """Create U2M authenticated client"""
        if not self._auth_context or not self._auth_context.user_token:
            raise ValueError("User token required for U2M authentication")
            
        try:
            # Use user's token directly for U2M
            client = WorkspaceClient(
                host=workspace_url,
                token=self._auth_context.user_token
            )
            
            # Validate client
            try:
                user_info = client.current_user.me()
                logger.info(f"U2M client created successfully for user: {user_info.user_name}")
            except Exception as e:
                logger.warning(f"U2M client created but validation failed: {e}")
                
            logger.info(f"Created U2M client for workspace: {workspace_url}")
            return client
            
        except Exception as e:
            logger.error(f"Failed to create U2M client: {e}")
            raise
    
    def _get_cache_key(self, workspace_url: str, auth_method: AuthMethod) -> str:
        """Generate cache key for client"""
        user_hash = hashlib.md5(
            (self._auth_context.user_email or "unknown").encode()
        ).hexdigest()[:8]
        return f"{workspace_url}:{auth_method.value}:{user_hash}"
    
    def _get_cached_client(self, workspace_url: str, auth_method: AuthMethod) -> Optional[WorkspaceClient]:
        """Get cached client if available and valid"""
        cache_key = self._get_cache_key(workspace_url, auth_method)
        
        with self._cache_lock:
            client = self._client_cache.get(cache_key)
            if client:
                try:
                    # Validate client by making a lightweight call
                    client.current_user.me()
                    return client
                except Exception as e:
                    logger.warning(f"Cached client invalid, removing: {e}")
                    del self._client_cache[cache_key]
            return None
    
    def _cache_client(self, workspace_url: str, auth_method: AuthMethod, client: WorkspaceClient):
        """Cache client for reuse"""
        cache_key = self._get_cache_key(workspace_url, auth_method)
        
        with self._cache_lock:
            self._client_cache[cache_key] = client
            
            # Cleanup old entries (simple LRU - keep last 10)
            if len(self._client_cache) > 10:
                oldest_key = next(iter(self._client_cache))
                del self._client_cache[oldest_key]
    
    def get_client(self, 
                   target_workspace: Optional[str] = None,
                   operation_type: Optional[str] = None,
                   force_auth_method: Optional[AuthMethod] = None) -> WorkspaceClient:
        """
        Get authenticated Databricks client with automatic auth method selection
        Considers OBO scope availability when choosing auth method
        
        This is the main method existing code should call instead of creating WorkspaceClient directly
        
        Args:
            target_workspace: Target workspace URL (for cross-workspace detection)
            operation_type: Type of operation being performed (for scope validation)
            force_auth_method: Force specific auth method (overrides auto-detection)
            
        Returns:
            Authenticated WorkspaceClient
        """
        if not self._auth_context:
            raise ValueError("Authentication context not set. Call set_auth_context() first.")
        
        workspace_url = target_workspace or self.workspace_url
        auth_method = force_auth_method or self._determine_auth_method(
            target_workspace=target_workspace,
            operation_type=operation_type
        )
        
        # Additional scope validation for OBO
        if auth_method == AuthMethod.OBO and operation_type:
            if not self.validate_operation_scope(operation_type):
                logger.warning(f"OBO scopes don't support '{operation_type}'. Switching to U2M.")
                auth_method = AuthMethod.U2M
        
        # Try to get cached client first
        client = self._get_cached_client(workspace_url, auth_method)
        if client:
            logger.debug(f"Using cached {auth_method.value} client for {workspace_url}")
            return client
        
        # Create new client
        try:
            if auth_method == AuthMethod.OBO:
                client = self._create_obo_client(workspace_url)
            else:  # U2M
                client = self._create_u2m_client(workspace_url)
                
            # Cache for future use
            self._cache_client(workspace_url, auth_method, client)
            
            logger.info(f"Created new {auth_method.value} client for {workspace_url}")
            return client
            
        except Exception as e:
            # Enhanced fallback logic with scope consideration
            if not force_auth_method:
                fallback_method = AuthMethod.U2M if auth_method == AuthMethod.OBO else AuthMethod.OBO
                
                # Don't fallback to OBO if scopes don't support the operation
                if fallback_method == AuthMethod.OBO and operation_type:
                    if not self.validate_operation_scope(operation_type):
                        logger.error(f"Fallback to OBO not possible due to scope limitations for '{operation_type}'")
                        raise
                
                logger.warning(f"Primary auth method {auth_method.value} failed, trying {fallback_method.value}")
                return self.get_client(
                    target_workspace=target_workspace,
                    operation_type=operation_type,
                    force_auth_method=fallback_method
                )
            raise
    
    def clear_cache(self):
        """Clear all cached clients"""
        with self._cache_lock:
            self._client_cache.clear()
            logger.info("Cleared client cache")

# Convenience wrapper that mimics WorkspaceClient interface
class SmartWorkspaceClient:
    """
    Drop-in replacement for WorkspaceClient that automatically handles auth method switching
    """
    
    def __init__(self, auth_manager: DatabricksAuthManager):
        self.auth_manager = auth_manager
        self._current_client: Optional[WorkspaceClient] = None
    
    def _get_client(self, **kwargs) -> WorkspaceClient:
        """Get appropriate client based on context"""
        return self.auth_manager.get_client(**kwargs)
    
    # Proxy all WorkspaceClient methods to the appropriate authenticated client
    def __getattr__(self, name):
        """Proxy attribute access to the underlying WorkspaceClient"""
        def wrapper(*args, **kwargs):
            # Extract context hints from kwargs if present
            target_workspace = kwargs.pop('target_workspace', None)
            operation_type = kwargs.pop('operation_type', None)
            
            client = self._get_client(
                target_workspace=target_workspace,
                operation_type=operation_type
            )
            
            method = getattr(client, name)
            return method(*args, **kwargs)
        
        return wrapper

# Integration helper for existing agent code
class DatabricksClientFactory:
    """
    Factory class to create authenticated clients with minimal changes to existing code
    Handles OBO scope configuration
    """
    
    @staticmethod
    def create_client(user_token: str, 
                     user_email: str,
                     workspace_url: str,
                     current_workspace_url: Optional[str] = None,
                     default_auth_method: AuthMethod = AuthMethod.AUTO,
                     obo_scope_config: Optional[OBOScopeConfig] = None,
                     agent_type: Optional[str] = None) -> SmartWorkspaceClient:
        """
        Create a smart workspace client that handles auth method switching and OBO scopes
        
        This is the main entry point for existing agent code
        Replace: client = WorkspaceClient(...)
        With: client = DatabricksClientFactory.create_client(...)
        
        Args:
            user_token: User's authentication token
            user_email: User's email
            workspace_url: Primary workspace URL
            current_workspace_url: Current/local workspace URL 
            default_auth_method: Default auth method
            obo_scope_config: OBO scope configuration (optional)
            agent_type: Agent type for automatic scope configuration ('basic', 'analytics', 'full')
        """
        # Handle OBO scope configuration
        if not obo_scope_config:
            if agent_type:
                obo_scope_config = OBOScopeConfig.for_agent_type(agent_type)
            else:
                obo_scope_config = OBOScopeConfig.from_env()
        
        auth_manager = DatabricksAuthManager(
            workspace_url=workspace_url,
            default_auth_method=default_auth_method,
            current_workspace_url=current_workspace_url,
            obo_scope_config=obo_scope_config
        )
        
        auth_manager.set_auth_context(
            user_token=user_token,
            user_email=user_email
        )
        
        return SmartWorkspaceClient(auth_manager)
    
    @staticmethod
    def create_with_custom_scopes(user_token: str,
                                 user_email: str, 
                                 workspace_url: str,
                                 obo_scopes: List[str],
                                 scope_description: str = "Custom agent scopes",
                                 **kwargs) -> SmartWorkspaceClient:
        """
        Create client with custom OBO scopes
        
        Args:
            user_token: User's authentication token
            user_email: User's email
            workspace_url: Primary workspace URL
            obo_scopes: List of OBO scopes
            scope_description: Description for the scopes
            **kwargs: Additional arguments for create_client
        """
        obo_scope_config = OBOScopeConfig(
            scopes=obo_scopes,
            description=scope_description
        )
        
        return DatabricksClientFactory.create_client(
            user_token=user_token,
            user_email=user_email,
            workspace_url=workspace_url,
            obo_scope_config=obo_scope_config,
            **kwargs
        )

# Context manager for operation-specific auth requirements
class AuthenticationContext:
    """
    Context manager for operations that need specific auth requirements
    """
    
    def __init__(self, client: SmartWorkspaceClient, **context_kwargs):
        self.client = client
        self.context_kwargs = context_kwargs
    
    def __enter__(self):
        return self.client
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Could add cleanup logic here if needed
        pass
