"""
Pytest configuration and fixtures
"""

import pytest

# pytest-httpx provides the httpx_mock fixture automatically
# when installed, so we just need to configure markers

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "httpx_mock: mark test as using httpx mock"
    )
