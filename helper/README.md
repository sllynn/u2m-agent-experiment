# Databricks AnyAuth

A flexible authentication utility for Databricks APIs.

## Installation

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd databricks-anyauth

# Install in development mode
pip install -e .

# Or build and install
pip install build
python -m build
pip install dist/databricks_anyauth-*.whl
```

### From PyPI (when published)

```bash
pip install databricks-anyauth
```

## Usage

```python
from databricks.anyauth import AnyAuth

# Token-based authentication
auth = AnyAuth(token="your-personal-access-token")

# Basic authentication
auth = AnyAuth(username="your-username", password="your-password")

# Get authentication headers for API requests
headers = auth.get_auth_headers()

# Test authentication
is_valid = auth.authenticate("https://your-workspace.cloud.databricks.com")
```

## Development

### Setup Development Environment

```bash
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black src/
```

### Type Checking

```bash
mypy src/
```

## Building

To build a wheel:

```bash
python -m build
```

This will create both a source distribution and a wheel in the `dist/` directory.

## License

MIT License
