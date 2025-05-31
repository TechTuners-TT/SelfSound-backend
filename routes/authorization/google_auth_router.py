import os
import uuid
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from config import GOOGLE_CLIENT_ID, GOOGLE_AUTH_URL, GOOGLE_REDIRECT_URI, GOOGLE_CLIENT_SECRET
from jwt_handler import generate_jwt, decode_jwt
from supabase_client import supabase
from typing import Optional
import httpx
import urllib.parse

router = APIRouter()

IS_TESTING = os.getenv("TESTING", "false").lower() == "true"


def get_cookie_security_settings():
    """Get cookie security settings based on environment"""
    environment = os.getenv("ENVIRONMENT", "development")

    if environment == "production":
        return {
            "httponly": True,
            "secure": True,  # HTTPS required for production
            "samesite": "none",  # Cross-site requests (GitHub Pages to Render)
            "max_age": 24 * 3600,
            "path": "/",
        }
    else:
        return {
            "httponly": True,
            "secure": False,  # HTTP for localhost development
            "samesite": "lax",  # Same-site for development
            "max_age": 24 * 3600,
            "path": "/",
        }


@router.get("/login")
def login(redirect_to: Optional[str] = None):
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }
    if redirect_to:
        params["state"] = urllib.parse.quote(redirect_to)

    url = f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)


@router.get("/callback")
async def auth_callback(request: Request):
    error = request.query_params.get("error")
    code = request.query_params.get("code")
    redirect_to = request.query_params.get("state", "https://techtuners-tt.github.io/SelfSound/#/home")

    if error == "access_denied":
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-up")

    if not code:
        raise HTTPException(status_code=400, detail="Authorization code is missing")

    try:
        google_response = await exchange_code_for_token(code)
        id_token_str = google_response.get('id_token')
        if not id_token_str:
            raise HTTPException(status_code=400, detail="ID token is missing")

        id_info = id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        email = id_info.get("email")
        login = email.split("@")[0]
        name = id_info.get("name")
        avatar_url = id_info.get("picture")
        sub = id_info.get("sub")

        user_id = str(uuid.uuid4())

        user_record = {
            "id": user_id,
            "email": email,
            "name": name,
            "picture": avatar_url,
            "sub": sub,
            "provider": "google",
            "verified": True
        }

        existing_user = supabase.from_("users").select("*").eq("sub", sub).execute()
        if not existing_user.data:
            supabase.from_("users").insert(user_record).execute()
        else:
            user_id = existing_user.data[0]["id"]

        user_profile = {
            "id": user_id,
            "name": name,
            "login": login,
            "avatar_url": avatar_url,
            "sub": sub,
            "email": email
        }

        existing_profile = supabase.from_("user_profiles").select("id").eq("sub", sub).execute()
        if not existing_profile.data:
            supabase.from_("user_profiles").insert(user_profile).execute()

        jwt_token = generate_jwt(id_info)

        # ✅ USE DYNAMIC COOKIE SETTINGS INSTEAD OF HARDCODED
        cookie_settings = get_cookie_security_settings()

        # Add debug logging
        print(f"🔍 Google Auth - Environment: {os.getenv('ENVIRONMENT', 'development')}")
        print(f"🔍 Google Auth - Cookie settings: {cookie_settings}")
        print(f"🔍 Google Auth - Generated token: {jwt_token[:50]}...")

        response = RedirectResponse(url=redirect_to, status_code=302)
        response.set_cookie(
            key="access_token",
            value=jwt_token,
            **cookie_settings  # ✅ Use dynamic settings instead of hardcoded
        )
        return response

    except ValueError:
        raise HTTPException(status_code=401, detail="Token verification failed")
    except httpx.HTTPStatusError as http_error:
        raise HTTPException(status_code=http_error.response.status_code, detail=f"HTTP error occurred: {http_error}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")


async def exchange_code_for_token(code: str):
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail="Error exchanging code for tokens")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An error occurred during token exchange: {str(e)}")


@router.get("/me/raw")
def get_current_user_raw(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Декодуємо кастомний JWT без перевірки audience та issuer
        user_info = decode_jwt(token, verify_aud_iss=False)
        return JSONResponse(content={"user": user_info})
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# ===== DEBUG ENDPOINT FOR GOOGLE AUTH =====
@router.get("/debug-google-cookies")
def debug_google_cookies(request: Request):
    """Debug Google auth cookies"""
    cookies = request.cookies
    environment = os.getenv("ENVIRONMENT", "development")
    cookie_settings = get_cookie_security_settings()

    return {
        "received_cookies": dict(cookies),
        "access_token_present": "access_token" in cookies,
        "access_token_value": cookies.get("access_token", "NOT_FOUND")[:50] if cookies.get(
            "access_token") else "NOT_FOUND",
        "environment": environment,
        "cookie_settings": cookie_settings,
        "auth_type": "google",
        "all_headers": dict(request.headers)
    }