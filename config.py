# auth/config.py

from starlette.config import Config

# Load environment variables from .env file
config = Config(".env")

GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = config("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = config("GOOGLE_REDIRECT_URI")
JWT_SECRET = config("JWT_SECRET")
JWT_ALGORITHM = config("JWT_ALGORITHM")
GOOGLE_AUTH_URL = config("GOOGLE_AUTH_URL")