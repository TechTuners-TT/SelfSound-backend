
import jwt
from datetime import datetime, timedelta

from config import JWT_SECRET, JWT_ALGORITHM


def generate_jwt(id_info: dict) -> str:
    """
    Generate a JWT token using Google ID token info.
    """
    payload = {
        "sub": id_info.get("sub"),
        "email": id_info.get("email"),
        "name": id_info.get("name"),
        "picture": id_info.get("picture"),
        "exp": datetime.utcnow() + timedelta(hours=1)
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt(token: str) -> dict:
    """
    Decode a JWT token and return the payload if valid.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
