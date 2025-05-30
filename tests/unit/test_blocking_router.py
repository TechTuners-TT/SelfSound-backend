import pytest
from unittest.mock import patch, MagicMock
from uuid import uuid4
from fastapi import HTTPException

from routes.blocking_router import block_user, unblock_user, get_blocked_users

# Мокований поточний користувач (dict-подібний)
mock_current_user = {"id": str(uuid4())}

# Моковані user_id
mock_target_user_id = str(uuid4())


@patch("routes.blocking_router.supabase")
def test_block_user_success(mock_supabase):
    mock_insert = MagicMock()
    mock_insert.execute.return_value.error = None
    mock_supabase.table.return_value.insert.return_value = mock_insert

    result = block_user(user_id=mock_target_user_id, current_user=mock_current_user)
    assert result == {"detail": "User blocked"}


@patch("routes.blocking_router.supabase")
def test_block_user_self_error(mock_supabase):
    with pytest.raises(HTTPException) as exc_info:
        block_user(user_id=mock_current_user["id"], current_user=mock_current_user)
    assert exc_info.value.status_code == 400
    assert "Cannot block yourself" in str(exc_info.value.detail)


@patch("routes.blocking_router.supabase")
def test_block_user_insert_error(mock_supabase):
    mock_error = MagicMock()
    mock_error.message = "Insert failed"
    mock_insert = MagicMock()
    mock_insert.execute.return_value.error = mock_error
    mock_supabase.table.return_value.insert.return_value = mock_insert

    with pytest.raises(HTTPException) as exc_info:
        block_user(user_id=mock_target_user_id, current_user=mock_current_user)
    assert exc_info.value.status_code == 400
    assert "Insert failed" in str(exc_info.value.detail)


@patch("routes.blocking_router.supabase")
def test_unblock_user_success(mock_supabase):
    mock_delete = MagicMock()
    mock_delete.execute.return_value.error = None
    mock_supabase.table.return_value.delete.return_value.match.return_value = mock_delete

    result = unblock_user(user_id=mock_target_user_id, current_user=mock_current_user)
    assert result == {"detail": "User unblocked"}


@patch("routes.blocking_router.supabase")
def test_unblock_user_error(mock_supabase):
    mock_error = MagicMock()
    mock_error.message = "Delete failed"
    mock_delete = MagicMock()
    mock_delete.execute.return_value.error = mock_error
    mock_supabase.table.return_value.delete.return_value.match.return_value = mock_delete

    with pytest.raises(HTTPException) as exc_info:
        unblock_user(user_id=mock_target_user_id, current_user=mock_current_user)
    assert exc_info.value.status_code == 400
    assert "Delete failed" in str(exc_info.value.detail)


@patch("routes.blocking_router.supabase")
def test_get_blocked_users_empty(mock_supabase):
    # Return empty list of blocked users
    mock_blocked_response = MagicMock()
    mock_blocked_response.execute.return_value.error = None
    mock_blocked_response.execute.return_value.data = []

    mock_supabase.from_.return_value.select.return_value.eq.return_value = mock_blocked_response

    result = get_blocked_users(current_user=mock_current_user)
    assert result == []


@patch("routes.blocking_router.supabase")
def test_get_blocked_users_success(mock_supabase):
    blocked_ids = [str(uuid4()), str(uuid4())]

    # blocked_users query
    mock_blocked_response = MagicMock()
    mock_blocked_response.execute.return_value.error = None
    mock_blocked_response.execute.return_value.data = [{"blocked_id": bid} for bid in blocked_ids]
    mock_supabase.from_.return_value.select.return_value.eq.return_value = mock_blocked_response

    # user_profiles query
    mock_profiles_response = MagicMock()
    mock_profiles_response.execute.return_value.error = None
    mock_profiles_response.execute.return_value.data = [
        {"id": blocked_ids[0], "login": "user1", "name": "User One"},
        {"id": blocked_ids[1], "login": "user2", "name": "User Two"}
    ]
    mock_supabase.from_.return_value.select.return_value.in_.return_value = mock_profiles_response

    result = get_blocked_users(current_user=mock_current_user)
    assert len(result) == 2
    assert result[0]["login"] == "user1"
    assert result[1]["login"] == "user2"
