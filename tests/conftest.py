"""
tests/conftest.py — shared pytest fixtures.
"""
import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: marks tests requiring Docker or external services (skip with -m 'not integration')",
    )
