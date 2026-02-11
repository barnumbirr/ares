"""Shared test fixtures."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from ares import VulnLookup

@pytest.fixture
def client():
    """Unauthenticated client."""
    with VulnLookup() as c:
        yield c

@pytest.fixture
def auth_client():
    """Client with an API key."""
    with VulnLookup(api_key="test-key") as c:
        yield c

@pytest.fixture
def runner():
    """Click CLI test runner."""
    return CliRunner()
