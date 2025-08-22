"""
Databricks authentication utilities.

This module provides authentication utilities for Databricks.
"""

__version__ = "0.1.0"

from .auth import (
    OBOScopes,
    OBOScopeConfig,
    AuthMethod,
    AuthContext,
    DatabricksAuthManager,
    SmartWorkspaceClient,
    DatabricksClientFactory,
    AuthenticationContext
)

__all__ = [
    "OBOScopes",
    "OBOScopeConfig", 
    "AuthMethod",
    "AuthContext",
    "DatabricksAuthManager",
    "SmartWorkspaceClient",
    "DatabricksClientFactory",
    "AuthenticationContext"
]
