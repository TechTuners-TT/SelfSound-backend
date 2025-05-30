import pytest
from unittest.mock import MagicMock
from uuid import uuid4

@pytest.fixture
def mock_current_user():
    """Creates a mock user for testing."""
    user = MagicMock()
    user.id = uuid4()
    user.email = "test@example.com"
    user.name = "Test User"
    return user

@pytest.fixture
def sample_user_profiles():
    """Returns sample user profile data."""
    return [
        {
            "id": str(uuid4()),
            "name": "User One",
            "username": "user1",
            "avatar_url": "https://example.com/avatar1.png",
            "description": "User one description",
            "tag_id": str(uuid4()),
            "email": "user1@example.com"
        },
        {
            "id": str(uuid4()),
            "name": "User Two",
            "username": "user2",
            "avatar_url": "https://example.com/avatar2.png",
            "description": "User two description",
            "tag_id": str(uuid4()),
            "email": "user2@example.com"
        }
    ]

@pytest.fixture
def sample_blocked_users():
    """Returns sample blocked users data."""
    return [
        {
            "id": str(uuid4()),
            "blocker_id": str(uuid4()),
            "blocked_id": str(uuid4()),
            "created_at": "2025-05-03T10:00:00Z"
        },
        {
            "id": str(uuid4()),
            "blocker_id": str(uuid4()),
            "blocked_id": str(uuid4()),
            "created_at": "2025-05-03T11:00:00Z"
        }
    ]