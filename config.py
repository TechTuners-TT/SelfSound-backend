from starlette.config import Config


# Load environment variables from .env file
config = Config(".env")

# All environment variables consistently using uppercase naming
FRONTEND_REDIRECT_URL = config("FRONTEND_REDIRECT_URL")
GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = config("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = config("GOOGLE_REDIRECT_URI")
JWT_SECRET = config("JWT_SECRET")
JWT_ALGORITHM = config("JWT_ALGORITHM")
GOOGLE_AUTH_URL = config("GOOGLE_AUTH_URL")
SUPABASE_URL = config("SUPABASE_URL")
SUPABASE_KEY = config("SUPABASE_KEY")  # Changed from lowercase to uppercase for consistency
API_URL = config("API_URL")
EMAIL_SENDER = config("EMAIL_SENDER")
VERIFICATION_TOKEN_EXP_HOURS = config("VERIFICATION_TOKEN_EXP_HOURS")  # Fixed missing config() call
EMAIL_PASSWORD = config("EMAIL_PASSWORD")  # Fixed missing config() call
SMTP_PORT = config("SMTP_PORT", cast=int)
SMTP_HOST = config("SMTP_HOST")
SMTP_PASSWORD = config("SMTP_PASSWORD")
SMTP_USER = config("SMTP_USER")
BUCKET_NAME = config("BUCKET_NAME")
SUPABASE_ISSUER = config("SUPABASE_ISSUER")
SUPABASE_AUDIENCE=config("SUPABASE_AUDIENCE")
GOOGLE_ISSUERS = config("GOOGLE_ISSUERS")
JWT_ALGORITHM_GOOGLE = config("JWT_ALGORITHM_GOOGLE")
GOOGLE_JWKS_URL = config("GOOGLE_JWKS_URL")
