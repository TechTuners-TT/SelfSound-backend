import jwt
from jwt import PyJWKClient, PyJWTError
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jwt import decode as jwt_decode
from config import (
    JWT_SECRET,
    JWT_ALGORITHM,
    SUPABASE_ISSUER,
    SUPABASE_AUDIENCE,
    GOOGLE_JWKS_URL,
    GOOGLE_CLIENT_ID
)


def generate_jwt(id_info: Dict[str, str]) -> str:
    """
    Generate a custom JWT token using Google ID token info.
    Adds 'iss' to support decoding logic based on issuer.
    """
    expiration = datetime.utcnow() + timedelta(hours=1)
    payload = {
        "sub": id_info.get("sub"),
        "email": id_info.get("email"),
        "name": id_info.get("name"),
        "picture": id_info.get("picture"),
        "iat": datetime.utcnow(),
        "exp": expiration,
        "iss": SUPABASE_ISSUER ,
        "aud": SUPABASE_AUDIENCE

    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_access_token(data: Dict[str, str], expires_delta: timedelta = timedelta(hours=1)) -> str:
    """
    Create a Supabase-compatible JWT token with `aud` and `iss` claims.
    """
    expiration = datetime.utcnow() + expires_delta
    payload = {
        "sub": data.get("sub"),
        "email": data.get("email"),
        "name": data.get("name"),
        "picture": data.get("picture"),
        "iat": datetime.utcnow(),
        "exp": expiration,
        "aud": SUPABASE_AUDIENCE,
        "iss": SUPABASE_ISSUER
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


google_jwks_client = PyJWKClient(GOOGLE_JWKS_URL)

def decode_jwt(token: str, leeway_seconds: int = 10, verify_aud_iss: bool = True) -> dict:
    try:
        # Розбираємо без перевірки, щоб подивитись issuer (якщо є)
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
        issuer = unverified_claims.get("iss")

        if issuer == SUPABASE_ISSUER:
            payload = jwt.decode(
                token,
                key=JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                audience=SUPABASE_AUDIENCE if verify_aud_iss else None,
                leeway=leeway_seconds,
                options={"verify_iss": False}
            )
            if verify_aud_iss and payload.get("iss") != SUPABASE_ISSUER:
                raise jwt.InvalidIssuerError("Invalid issuer")
            return payload

        elif issuer and "accounts.google.com" in issuer:
            signing_key = google_jwks_client.get_signing_key_from_jwt(token).key
            payload = jwt.decode(
                token,
                key=signing_key,
                algorithms=["RS256"],
                audience=GOOGLE_CLIENT_ID if verify_aud_iss else None,
                leeway=leeway_seconds,
                options={"verify_iss": False}
            )
            if verify_aud_iss and payload.get("iss") != issuer:
                raise jwt.InvalidIssuerError("Invalid issuer")
            return payload

        elif issuer is None:
            # Якщо issuer немає, вважаємо це локальний токен (з нашим секретом)
            payload = jwt.decode(
                token,
                key=JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                leeway=leeway_seconds,
                options={"verify_iss": False, "verify_aud": False}
            )
            return payload

        else:
            raise ValueError(f"Unknown or unsupported issuer: {issuer}")

    except jwt.PyJWTError as e:
        raise ValueError(f"Token decode error: {str(e)}")

