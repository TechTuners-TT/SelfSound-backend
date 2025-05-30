import pytest
from unittest.mock import patch, AsyncMock, MagicMock, ANY
from routes.authorization import default_auth_router as auth
from models.schemas.default_auth import UserCreate
from passlib.context import CryptContext
from datetime import datetime, timedelta

@pytest.fixture
def test_user():
    return UserCreate(
        email="test@example.com",
        password="Str0ngP@ssword!",
        name="Test User"
    )

@pytest.mark.asyncio
@patch("routes.authorization.default_auth_router.supabase")
@patch("routes.authorization.default_auth_router.send_verification_email", new_callable=AsyncMock)
async def test_sign_up_function(mock_send_email, mock_supabase, test_user):
    # No user exists yet
    mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value.data = []

    # User creation success
    mock_supabase.table.return_value.insert.return_value.execute.return_value.data = [{
        "id": "user-uuid",
        "email": test_user.email,
        "name": test_user.name,
        "provider": "email",
    }]

    # Insert token success
    mock_supabase.table.return_value.insert.return_value.execute.return_value.error = None

    result = await auth.sign_up(test_user)

    assert result["email"] == test_user.email
    mock_send_email.assert_awaited_once_with(test_user.email, ANY)

@pytest.mark.asyncio
@patch("routes.authorization.default_auth_router.supabase")
async def test_login_function(mock_supabase, test_user):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_context.hash(test_user.password)

    # Simulate found user
    mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
        {"email": test_user.email, "password": hashed_password}
    ]

    result = await auth.login(test_user)

    assert result["message"] == "Login successful"

@pytest.mark.asyncio
@patch("routes.authorization.default_auth_router.supabase")
@patch("routes.authorization.default_auth_router.send_verification_email", new_callable=AsyncMock)
async def test_send_verification_email_endpoint(mock_send_email, mock_supabase):
    current_user = {"id": "user-uuid", "email": "test@example.com"}

    # User not verified
    mock_supabase.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value.data = {
        "verified": False
    }

    # Delete old tokens success
    mock_supabase.table.return_value.delete.return_value.eq.return_value.execute.return_value.error = None

    # Insert token success
    mock_supabase.table.return_value.insert.return_value.execute.return_value.error = None

    result = await auth.send_verification_email_endpoint(current_user)

    assert result["message"] == "Verification email sent"
    mock_send_email.assert_awaited_once_with(current_user["email"], ANY)

@pytest.mark.asyncio
@patch("routes.authorization.default_auth_router.supabase")
async def test_verify_email_success(mock_supabase):
    token = "valid-token"
    user_id = "user-uuid"
    expires_at = (datetime.utcnow() + timedelta(minutes=30)).isoformat()

    # Mock for token query: .single().execute()
    token_result = MagicMock()
    token_result.get.return_value = None
    token_result.data = {
        "user_id": user_id,
        "token": token,
        "expires_at": expires_at
    }

    # Mock for user query: .single().execute()
    user_result = MagicMock()
    user_result.get.return_value = None
    user_result.data = {"verified": False}

    # Configure the .single().execute() chain
    token_selector = MagicMock()
    token_selector.execute.return_value = token_result

    user_selector = MagicMock()
    user_selector.execute.return_value = user_result

    # Return token_selector first, then user_selector on second call
    mock_supabase.table.return_value.select.return_value.eq.return_value.single.side_effect = [
        token_selector,
        user_selector
    ]

    # Mocks for update and delete
    mock_supabase.table.return_value.update.return_value.eq.return_value.execute.return_value = MagicMock(error=None)
    mock_supabase.table.return_value.delete.return_value.eq.return_value.execute.return_value = MagicMock(error=None)

    result = await auth.verify_email(token=token)

    assert result["message"] == "Email verified successfully"
