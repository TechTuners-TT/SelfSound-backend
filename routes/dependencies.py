from fastapi import Request, HTTPException
from supabase_client import supabase
from jwt_handler import decode_jwt


async def get_verified_user(request: Request):
    token = None
    auth_source = None

    # MOBILE AUTH: Try Authorization header first (works better on mobile)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        auth_source = "header"
        print(f"📱 MOBILE AUTH: Found Bearer token in Authorization header: {token[:50]}...")

    # WEB AUTH: Fallback to cookies
    if not token:
        token = request.cookies.get("access_token")
        auth_source = "cookie"
        print(f"🍪 WEB AUTH: Access token from cookies: {token[:50] if token else 'None'}...")

    if not token:
        print("❌ [get_verified_user] No token found in header or cookies")
        raise HTTPException(status_code=401, detail="No authentication token provided")

    print(f"✅ [get_verified_user] Using token from: {auth_source}")

    try:
        payload = decode_jwt(token)
        print(f"🔓 [get_verified_user] Decoded JWT payload: {payload}")

        user_sub = payload.get("sub")
        user_email = payload.get("email")
        print(f"👤 [get_verified_user] Extracted sub: {user_sub}, email: {user_email}")

        if not user_sub and not user_email:
            print("❌ [get_verified_user] No user identifier found in token")
            raise HTTPException(status_code=401, detail="Invalid token: missing user identifier")

        user_resp = None

        # Try to find user by sub first
        if user_sub:
            user_resp = supabase.table("users").select("*").eq("sub", user_sub).single().execute()
            print(f"🔍 [get_verified_user] Supabase response data (by sub): {user_resp.data}")

        # Fallback to email if sub lookup failed
        if (user_resp is None or user_resp.data is None) and user_email:
            user_resp = supabase.table("users").select("*").eq("email", user_email).single().execute()
            print(f"🔍 [get_verified_user] Supabase fallback response data (by email): {user_resp.data}")

        if user_resp is None or user_resp.data is None:
            print("❌ [get_verified_user] User not found in database")
            raise HTTPException(status_code=401, detail="User not found")

        user_data = user_resp.data
        provider = user_data.get("provider", "email")
        is_verified = user_data.get("verified", False)

        # Check email verification for email users
        if provider == "email" and not is_verified:
            print("⚠️ [get_verified_user] Email user is not verified")
            raise HTTPException(status_code=403, detail="Email not verified")

        print(f"🎉 [get_verified_user] Successfully verified user: {user_data.get('email')} via {auth_source}")

        return {
            "id": user_data.get("id"),
            "sub": user_data.get("sub"),
            "email": user_data.get("email"),
            "name": user_data.get("name", ""),
            "verified": is_verified,
            "provider": provider,
            "email_confirmed": is_verified or provider != "email",
        }

    except ValueError as ve:
        print(f"❌ [get_verified_user] JWT decode error: {str(ve)}")
        if "expired" in str(ve).lower():
            raise HTTPException(status_code=401, detail="Token has expired")
        else:
            raise HTTPException(status_code=401, detail="Invalid token")
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 [get_verified_user] Unexpected error: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")
