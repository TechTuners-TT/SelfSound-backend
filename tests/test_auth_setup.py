"""
This module provides authentication setup for testing FastAPI endpoints that require
authentication. It provides utilities to mock authentication dependencies during tests.
"""

from unittest.mock import patch, MagicMock
from uuid import uuid4

def get_mock_user():
    """
    Create a mock user for testing authentication.

    Returns:
        A mock user object with basic properties set.
    """
    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_user.email = "test@example.com"
    mock_user.name = "Test User"
    return mock_user

def mock_get_current_user():
    """
    A synchronous version of the get_current_user function for testing.

    Returns:
        A mock user object.
    """
    return get_mock_user()

async def async_mock_get_current_user():
    """
    An asynchronous version of the get_current_user function for testing.

    Returns:
        A mock user object.
    """
    return get_mock_user()