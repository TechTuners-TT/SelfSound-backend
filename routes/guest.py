from fastapi import Request
from jwt_handler import decode_jwt

async def get_optional_user(request: Request):
    token = request.cookies.get("access_token")
    if token:
        try:
            user = decode_jwt(token)
            return user
        except Exception:
            # Optional: логування або повернення None
            return None
    return None
