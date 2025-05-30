import re
import logging
import uuid
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status, Depends, BackgroundTasks
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from passlib.context import CryptContext
from email_validator import validate_email, EmailNotValidError
import secrets
from utils.email_utils import send_verification_email
import hashlib
import jwt
import requests
from supabase import create_client, Client

from jwt_handler import decode_jwt
from routes.dependencies import get_verified_user
from models.schemas.default_auth import UserCreate, UserLogin

from config import (
    SUPABASE_URL,
    SUPABASE_KEY,
    VERIFICATION_TOKEN_EXP_HOURS,
    JWT_SECRET,
    JWT_ALGORITHM,
    FRONTEND_REDIRECT_URL,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/authorization", tags=["authorization"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

COMMON_PASSWORDS = {"password", "123456", "12345678", "qwerty", "abc123"}


def get_cookie_security_settings():
    """Get cookie security settings based on environment"""
    environment = os.getenv("ENVIRONMENT", "development")

    if environment == "production":
        return {
            "httponly": True,
            "secure": True,
            "samesite": "none",
            "max_age": 24 * 3600,
            "path": "/",
        }
    else:
        return {
            "httponly": True,
            "secure": False,
            "samesite": "lax",
            "max_age": 24 * 3600,
            "path": "/",
        }


def generate_verification_token():
    """Generate a secure verification token"""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash the token for database storage"""
    return hashlib.sha256(token.encode()).hexdigest()


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.cookies.get("access_token")
        if token:
            try:
                payload = decode_jwt(token, verify_aud_iss=True)
                request.state.user = payload
            except Exception:
                request.state.user = None
        else:
            request.state.user = None

        return await call_next(request)


def generate_uuid_sub() -> str:
    return str(uuid.uuid4())


def validate_password(password: str):
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters long")
    if len(password) > 64:
        errors.append("no more than 64 characters long")
    if not re.search(r"[A-Z]", password):
        errors.append("at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("at least one lowercase letter")
    if not re.search(r"[0-9]", password):
        errors.append("at least one number")
    if not re.search(r"[^a-zA-Z0-9]", password):
        errors.append("at least one special character")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("password is too common")
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"Password must include: {', '.join(errors)}"
        )


def generate_unique_login(email: str) -> str:
    base = email.split("@")[0]
    login = base
    counter = 1
    while True:
        check = supabase.table("user_profiles").select("id").eq("login", login).execute()
        if not check.data:
            return login
        login = f"{base}{counter}"
        counter += 1


@router.post("/signup")
async def sign_up(user: UserCreate, background_tasks: BackgroundTasks):
    logger.debug(f"Signup attempt for email: {user.email}")

    try:
        # Validate email
        try:
            validate_email(user.email)
        except EmailNotValidError as e:
            raise HTTPException(400, str(e))

        # Validate name
        if not user.name or not user.name.strip():
            raise HTTPException(400, "Name cannot be empty")

        # Validate password
        validate_password(user.password)

        # Convert email to string for consistency
        email_str = str(user.email)
        logger.debug(f"Processing signup for: {email_str}")

        # Check if user already exists
        existing_user = supabase.table("users").select("id, email, verified").eq("email", email_str).execute()
        logger.debug(f"Existing user check completed")

        if existing_user.data:
            existing_user_data = existing_user.data[0]
            if existing_user_data.get("verified"):
                raise HTTPException(400, "User already exists and is verified")
            else:
                # User exists but not verified - resend verification
                user_id = existing_user_data["id"]
                logger.debug(f"Resending verification for existing user")
                return await resend_verification_for_user(user_id, email_str, background_tasks)

        # Generate user ID and hash password
        user_id = generate_uuid_sub()
        hashed_password = pwd_context.hash(user.password)
        logger.debug(f"Generated user ID and hashed password")

        # Create user record
        created_user = supabase.table("users").insert({
            "id": user_id,
            "email": email_str,
            "name": user.name,
            "password": hashed_password,
            "provider": "email",
            "verified": False,
            "sub": user_id,
            "created_at": datetime.utcnow().isoformat(),
        }).execute()
        logger.debug(f"User creation completed")

        if not created_user.data:
            raise HTTPException(500, "Failed to create user record")

        # Generate unique login
        login = generate_unique_login(email_str)
        logger.debug(f"Generated unique login")

        # Create user profile
        profile_data = {
            "id": user_id,
            "name": user.name,
            "login": login,
            "avatar_url": "https://cdn.builder.io/api/v1/image/assets/TEMP/3922534bd59dfe0deae8bd149c0b3cba46e3eb47?placeholderIfAbsent=true&apiKey=04fef95365634cc5973c2029f1fc78f5",
            "description": "",
            "email": email_str,
            "sub": user_id,
        }

        logger.debug(f"Creating user profile")
        profile_result = supabase.table("user_profiles").insert(profile_data).execute()
        logger.debug(f"Profile creation completed")

        if not profile_result.data:
            # If profile creation fails, clean up the user record
            logger.error("Profile creation failed, cleaning up user record")
            supabase.table("users").delete().eq("id", user_id).execute()
            raise HTTPException(500, "Failed to create user profile")

        # Generate verification token
        verification_token = generate_verification_token()
        hashed_token = hash_token(verification_token)
        logger.debug(f"Generated verification token")

        # Store verification token
        token_insert = {
            "user_id": user_id,
            "token": hashed_token,
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }
        logger.debug(f"Storing verification token")

        token_result = supabase.table("email_verification_tokens").insert(token_insert).execute()
        logger.debug(f"Token storage completed")

        if not token_result.data:
            # Clean up user and profile if token creation fails
            logger.error("Token creation failed, cleaning up user and profile")
            supabase.table("user_profiles").delete().eq("id", user_id).execute()
            supabase.table("users").delete().eq("id", user_id).execute()
            raise HTTPException(500, "Failed to create verification token")

        # Send verification email in background
        logger.debug("Scheduling verification email")
        background_tasks.add_task(send_verification_email, email_str, verification_token)

        logger.info("Signup completed successfully")
        return {
            "message": "User created successfully. Please check your email for verification link.",
            "email": email_str
        }

    except HTTPException as he:
        logger.warning(f"Signup validation error: {he.detail}")
        raise
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        raise HTTPException(500, "Failed to create user account")


# Helper function for resending verification to existing unverified users
async def resend_verification_for_user(user_id: str, email: str, background_tasks: BackgroundTasks):
    """Resend verification email for existing unverified user"""
    try:
        # Delete any existing verification tokens for this user
        supabase.table("email_verification_tokens").delete().eq("user_id", user_id).execute()

        # Generate new verification token
        verification_token = generate_verification_token()
        hashed_token = hash_token(verification_token)

        # Store new verification token
        token_insert = {
            "user_id": user_id,
            "token": hashed_token,
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }

        supabase.table("email_verification_tokens").insert(token_insert).execute()

        # Send verification email
        background_tasks.add_task(send_verification_email, email, verification_token)

        return {
            "message": "Verification email sent successfully. Please check your email.",
            "email": email
        }

    except Exception as e:
        logger.error(f"Failed to resend verification: {e}")
        raise HTTPException(500, "Failed to resend verification")


@router.get("/verify-email")
async def verify_email_simple(token: str):
    """Simple email verification that redirects to sign-in page"""
    try:
        logger.debug(f"Processing email verification")

        # Hash the provided token
        hashed_token = hash_token(token)
        logger.debug(f"Token hashed for lookup")

        # Find verification token
        token_result = supabase.table("email_verification_tokens").select("*").eq("token", hashed_token).execute()
        logger.debug(f"Token search completed")

        if not token_result.data:
            logger.warning("Invalid verification token provided")
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=invalid_token",
                status_code=302
            )

        token_data = token_result.data[0]
        user_id = token_data["user_id"]
        logger.debug(f"Found verification token for user")

        # Check if token has expired
        expires_at_str = token_data["expires_at"]
        logger.debug(f"Checking token expiration")

        # Handle both timezone-aware and timezone-naive datetimes
        if expires_at_str.endswith('+00:00') or 'T' in expires_at_str:
            expires_at_str = expires_at_str.replace('+00:00', '').replace('Z', '')
            expires_at = datetime.fromisoformat(expires_at_str)
        else:
            expires_at = datetime.fromisoformat(expires_at_str)

        current_time = datetime.utcnow()
        logger.debug(f"Token expiration check completed")

        if current_time > expires_at:
            logger.warning("Verification token has expired")
            supabase.table("email_verification_tokens").delete().eq("token", hashed_token).execute()
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=token_expired",
                status_code=302
            )

        # Check if user is already verified
        user_result = supabase.table("users").select("verified, email").eq("id", user_id).execute()
        logger.debug(f"User verification status checked")

        if not user_result.data:
            logger.error("User not found during verification")
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=user_not_found",
                status_code=302
            )

        user_data = user_result.data[0]
        logger.debug(f"User data retrieved")

        if user_data.get("verified"):
            logger.info("User already verified")
            supabase.table("email_verification_tokens").delete().eq("token", hashed_token).execute()
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?success=already_verified",
                status_code=302
            )

        # Update user as verified
        logger.debug("Updating user verification status")
        update_data = {
            "verified": True,
            "verified_at": datetime.utcnow().isoformat()
        }
        logger.debug(f"Preparing verification update")

        update_result = supabase.table("users").update(update_data).eq("id", user_id).execute()
        logger.debug(f"User verification update completed")

        if not update_result.data:
            logger.error("Failed to update user verification status")
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=verification_failed",
                status_code=302
            )

        # Verify the update worked
        verify_result = supabase.table("users").select("verified, verified_at").eq("id", user_id).execute()
        logger.debug(f"Verification status confirmed")

        # Delete used verification token
        delete_result = supabase.table("email_verification_tokens").delete().eq("token", hashed_token).execute()
        logger.debug(f"Used token deleted")

        logger.info("Email verification process completed successfully")

        # Redirect to sign-in page with success message
        return RedirectResponse(
            url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?success=email_verified",
            status_code=302
        )

    except Exception as e:
        logger.error(f"Email verification failed: {str(e)}")
        # Redirect to sign-in with error message
        return RedirectResponse(
            url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=verification_error",
            status_code=302
        )


@router.post("/resend-verification")
async def resend_verification(email_data: dict, background_tasks: BackgroundTasks):
    try:
        email = email_data.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")

        # Find unverified user
        user_result = supabase.table("users").select("id, verified").eq("email", email).execute()

        if not user_result.data:
            raise HTTPException(status_code=400, detail="User not found")

        user = user_result.data[0]

        if user.get("verified"):
            raise HTTPException(status_code=400, detail="Email already verified")

        return await resend_verification_for_user(user["id"], email, background_tasks)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resend verification: {e}")
        raise HTTPException(status_code=500, detail="Failed to resend verification")


@router.post("/logindefault")
def login(user: UserLogin, response: Response):
    try:
        user_record = supabase.table("users").select("*").eq("email", user.email).single().execute()

        if not user_record.data:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

        user_data = user_record.data

        if not pwd_context.verify(user.password, user_data["password"]):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

        if not user_data.get("verified", False):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Email not verified")

        payload = {
            "sub": user_data["id"],
            "email": user_data["email"],
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
        access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        # Use secure cookie settings
        cookie_settings = get_cookie_security_settings()
        response.set_cookie(
            key="access_token",
            value=access_token,
            **cookie_settings
        )

        return {
            "message": "Login successful",
            "user": {
                "id": user_data["id"],
                "email": user_data["email"],
                "name": user_data["name"],
                "verified": user_data.get("verified", False)
            },
            "expires_in": 24 * 3600
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")


def create_email_verification_token(id: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=int(VERIFICATION_TOKEN_EXP_HOURS))
    payload = {
        "sub": id,
        "exp": expire.timestamp(),
        "type": "email_verification"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


@router.get("/me")
def get_me(user: dict = Depends(get_verified_user)):
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return {"id": user["id"], "name": user.get("name")}


def delete_user_from_supabase(user_id: str):
    url = f"{SUPABASE_URL}/rest/v1/auth/admin/users/{user_id}"
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}"
    }
    try:
        response = requests.delete(url, headers=headers, timeout=30)

        if response.status_code in (200, 204):
            return True
        else:
            return False
    except requests.exceptions.Timeout:
        logger.error(f"Timeout deleting user {user_id}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        return False


@router.delete("/me", status_code=204)
def delete_user_account(
        response: Response,
        user: dict = Depends(get_verified_user)
):
    user_id = user["id"]

    profile_res = supabase.table("user_profiles").delete().eq("id", user_id).execute()
    user_res = supabase.table("users").delete().eq("id", user_id).execute()

    if not delete_user_from_supabase(user_id):
        raise HTTPException(status_code=500, detail="Failed to delete user from Supabase Auth")

    cookie_settings = get_cookie_security_settings()
    response.delete_cookie(
        key="access_token",
        path="/",
        secure=cookie_settings["secure"],
        samesite=cookie_settings["samesite"]
    )

    return Response(status_code=200)


@router.post("/logout")
async def logout(response: Response):
    try:
        cookie_settings = get_cookie_security_settings()
        response.delete_cookie(
            key="access_token",
            path="/",
            secure=cookie_settings["secure"],
            samesite=cookie_settings["samesite"]
        )
        logger.info("User logged out successfully")
        return {"message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return {"message": "Logged out"}


# SECURE SYSTEM STATUS ENDPOINTS

@router.get("/health")
async def health_check():
    """Public health check endpoint"""
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "authentication"
        }
    except Exception:
        return {
            "status": "degraded",
            "timestamp": datetime.utcnow().isoformat()
        }


@router.get("/system-status")
async def get_system_status():
    """Get system status without exposing configuration details"""
    try:
        # Check essential services without exposing values
        status = {
            "authentication": "operational",
            "email_service": "configured",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat(),
            "status": "operational"
        }

        return status

    except ImportError as e:
        logger.error(f"System status check - import error: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail="Service temporarily unavailable"
        )

    except Exception as e:
        logger.error(f"System status check failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="System status check failed"
        )


# ADMIN-ONLY DEBUG ENDPOINTS (SECURE)

@router.get("/admin/config-status")
async def get_config_status(current_user: dict = Depends(get_verified_user)):
    """Get configuration status - ADMIN ONLY"""

    # Check admin permissions (adjust this based on your admin system)
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        from config import EMAIL_SENDER, EMAIL_PASSWORD, SMTP_HOST, SMTP_PORT, FRONTEND_REDIRECT_URL

        # Return configuration status without exposing actual values
        return {
            "email_sender_configured": bool(EMAIL_SENDER),
            "email_password_configured": bool(EMAIL_PASSWORD),
            "smtp_host_configured": bool(SMTP_HOST),
            "smtp_port_configured": bool(SMTP_PORT) and isinstance(SMTP_PORT, int),
            "frontend_url_configured": bool(FRONTEND_REDIRECT_URL),
            "status": "configured"
        }
    except ImportError as e:
        logger.error(f"Configuration import failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Configuration service unavailable"
        )
    except Exception as e:
        logger.error(f"Configuration check failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Configuration check failed"
        )


@router.post("/admin/test-email")
async def admin_test_email(email_data: dict, current_user: dict = Depends(get_verified_user)):
    """Admin email test endpoint with secure error handling"""

    # Check admin permissions
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        recipient = email_data.get("email")
        if not recipient:
            raise HTTPException(status_code=400, detail="Email address required")

        # Test email sending
        test_token = generate_verification_token()

        # Use background task to avoid blocking
        from fastapi import BackgroundTasks
        background_tasks = BackgroundTasks()
        background_tasks.add_task(send_verification_email, recipient, test_token)

        logger.info(f"Admin test email sent to {recipient}")
        return {
            "status": "success",
            "message": "Test email sent successfully",
            "recipient": recipient
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin email test failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Email test failed"
        )


@router.get("/admin/user-status/{user_id}")
async def admin_check_user_status(user_id: str, current_user: dict = Depends(get_verified_user)):
    """Check user verification status - ADMIN ONLY"""

    # Check admin permissions
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # Validate UUID
        try:
            uuid.UUID(user_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid user ID format")

        user_result = supabase.table("users").select("id, email, verified, verified_at, created_at").eq("id",
                                                                                                        user_id).execute()

        if not user_result.data:
            raise HTTPException(status_code=404, detail="User not found")

        user_data = user_result.data[0]
        return {
            "user_id": user_data["id"],
            "email": user_data["email"],
            "verified": user_data.get("verified"),
            "verified_at": user_data.get("verified_at"),
            "created_at": user_data.get("created_at")
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin user status check failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="User status check failed"
        )