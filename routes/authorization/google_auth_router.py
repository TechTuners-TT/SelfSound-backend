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

        response = RedirectResponse(url=redirect_to, status_code=302)
        response.set_cookie(
            key="access_token",
            value=jwt_token,
            httponly=True,
            secure=True,
            samesite="none",
            max_age=3600,
            path="/"
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
