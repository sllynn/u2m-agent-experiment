# Databricks Authentication Test Suite

This directory contains comprehensive tests for the Databricks authentication system that handles OBO (On-Behalf-Of) and U2M (User-to-Machine) authentication methods.

## Test Overview

The test suite covers:

- **OBO Scope Configuration**: Testing different OBO scope combinations and validation
- **Auth Method Selection**: Testing automatic selection between OBO and U2M based on context
- **Cross-Workspace vs Same-Workspace**: Testing different workspace scenarios
- **Client Creation and Caching**: Testing client lifecycle management
- **Error Handling**: Testing edge cases and error conditions
- **Integration Scenarios**: Testing real-world usage patterns

## Test Files

### `test_auth.py`
Core unit tests for all authentication classes and methods:

- **TestOBOScopes**: Tests OBO scope constants and predefined scope sets
- **TestOBOScopeConfig**: Tests scope configuration creation and validation
- **TestAuthMethod**: Tests authentication method enum
- **TestAuthContext**: Tests authentication context data structure
- **TestDatabricksAuthManager**: Tests the main authentication manager
- **TestDatabricksClientFactory**: Tests client factory methods
- **TestSmartWorkspaceClient**: Tests the smart client wrapper
- **TestAuthenticationContext**: Tests context manager functionality
- **TestIntegrationScenarios**: Tests integration scenarios
- **TestErrorHandling**: Tests error conditions and edge cases

### `test_auth_scenarios.py`
Advanced scenario tests for specific use cases:

- **TestOBOScopeScenarios**: Tests different OBO scope combinations
- **TestCrossWorkspaceScenarios**: Tests cross-workspace vs same-workspace operations
- **TestAgentTypeScenarios**: Tests different agent type configurations
- **TestEnvironmentVariableScenarios**: Tests environment-based configuration
- **TestCustomScopeScenarios**: Tests custom scope configurations
- **TestOperationTypeScenarios**: Tests different operation types and their scope requirements
- **TestEdgeCaseScenarios**: Tests edge cases and complex scenarios

## Running Tests

### Using the Test Runner Script

```bash
# Run all tests
python run_tests.py

# Run all tests in verbose mode
python run_tests.py -v

# Run specific test file
python run_tests.py tests/test_auth.py -v

# Run with coverage reporting
python run_tests.py -c

# Run with HTML coverage report
python run_tests.py -c --html-report
```

### Using pytest directly

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_auth.py

# Run specific test class
python -m pytest tests/test_auth.py::TestDatabricksAuthManager

# Run specific test method
python -m pytest tests/test_auth.py::TestDatabricksAuthManager::test_init_with_scope_config

# Run with verbose output
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=databricks.anyauth --cov-report=term-missing
```

## Test Scenarios Covered

### OBO Scope Testing

1. **Basic Agent Scopes**: Tests the predefined basic agent scope set
2. **Analytics Agent Scopes**: Tests analytics-focused scope configuration
3. **Full Agent Scopes**: Tests comprehensive scope configuration
4. **Custom Scopes**: Tests user-defined scope combinations
5. **Environment Variable Scopes**: Tests scope configuration from environment variables

### Authentication Method Selection

1. **Same-Workspace with OBO Scopes**: Tests OBO authentication when scopes are available
2. **Same-Workspace without OBO Scopes**: Tests fallback to U2M when scopes are missing
3. **Cross-Workspace Operations**: Tests U2M authentication for cross-workspace operations
4. **Forced Authentication Method**: Tests overriding automatic selection

### Operation Type Testing

1. **Vector Search Operations**: Tests vector search with appropriate scopes
2. **SQL Operations**: Tests SQL warehouse operations
3. **Serving Endpoint Operations**: Tests model serving operations
4. **Jobs Operations**: Tests job management operations
5. **Clusters Operations**: Tests cluster management operations
6. **Catalog Operations**: Tests catalog read/write operations

### Error Handling

1. **Missing Authentication Context**: Tests error when auth context is not set
2. **Missing User Token**: Tests error when user token is not provided
3. **Invalid Scope Configuration**: Tests behavior with invalid scopes
4. **Client Creation Failures**: Tests fallback behavior when client creation fails

### Integration Scenarios

1. **Client Caching**: Tests that clients are properly cached and reused
2. **Multiple Operation Types**: Tests handling multiple operation types in the same session
3. **Scope Validation**: Tests that operations are validated against available scopes
4. **Fallback Logic**: Tests fallback from OBO to U2M when needed

## Test Data and Mocking

The tests use extensive mocking to avoid requiring actual Databricks workspaces:

- **WorkspaceClient**: Mocked to avoid actual API calls
- **ModelServingUserCredentials**: Mocked for OBO authentication
- **Environment Variables**: Patched to test different configurations
- **User Tokens**: Mocked to avoid requiring real authentication

## Coverage

The test suite provides comprehensive coverage of:

- ✅ All public classes and methods
- ✅ All authentication method selection logic
- ✅ All OBO scope validation scenarios
- ✅ All error handling paths
- ✅ All client creation and caching logic
- ✅ All factory methods and convenience functions

## Adding New Tests

When adding new tests:

1. **Use descriptive test names**: Test names should clearly describe what is being tested
2. **Test one thing at a time**: Each test should focus on a single behavior or scenario
3. **Use appropriate mocking**: Mock external dependencies to keep tests fast and reliable
4. **Test edge cases**: Include tests for error conditions and boundary cases
5. **Follow the existing pattern**: Use the same structure and naming conventions as existing tests

## Example Test Structure

```python
def test_specific_scenario(self, mock_workspace_client):
    """Test description of what this test verifies."""
    with patch('databricks.anyauth.auth.ModelServingUserCredentials'):
        with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_workspace_client):
            # Setup
            scope_config = OBOScopeConfig(scopes=[OBOScopes.VECTOR_SEARCH])
            auth_manager = DatabricksAuthManager(
                workspace_url="https://test.workspace.com",
                current_workspace_url="https://test.workspace.com",
                obo_scope_config=scope_config
            )
            
            # Execute
            auth_manager.set_auth_context("test-token", "test@example.com")
            client = auth_manager.get_client(
                target_workspace="https://test.workspace.com",
                operation_type="vector_search"
            )
            
            # Assert
            assert client == mock_workspace_client
```

## Continuous Integration

These tests are designed to run in CI/CD pipelines:

- **Fast execution**: Tests complete in under 1 second
- **No external dependencies**: All tests use mocking
- **Deterministic results**: Tests produce consistent results
- **Comprehensive coverage**: Tests cover all critical code paths

## Troubleshooting

### Import Errors
If you encounter import errors, ensure the `src` directory is in your Python path:

```python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
```

### Mock Issues
If mocks aren't working as expected, check that you're patching the correct import path:

```python
# Correct way to patch
with patch('databricks.anyauth.auth.WorkspaceClient', return_value=mock_client):
    # test code here
```

### Test Failures
If tests fail, check:

1. **Import paths**: Ensure the test can import the modules being tested
2. **Mock setup**: Verify that mocks are properly configured
3. **Test isolation**: Ensure tests don't interfere with each other
4. **Environment variables**: Check that environment patches are working correctly
