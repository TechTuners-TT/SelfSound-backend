from supabase import create_client, Client
from config import SUPABASE_URL, SUPABASE_KEY
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
# Supabase credentials (URL and Key)
url = SUPABASE_URL  # Your Supabase URL, e.g.,
key = SUPABASE_KEY  # Your Supabase API key
supabase: Client = create_client(url, key)

# Helper functions to interact with Supabase
def get_user_by_email(email: str):
    """Get a user from Supabase by email"""
    response = supabase.table('users').select('*').eq('email', email).execute()
    return response.data

def create_user_in_db(email: str, password: str, name: str = None):
    """Create a new user in the Supabase 'users' table"""
    response = supabase.table('users').insert({
        'email': email,
        'password': password,  # This is a hashed password if you're using custom auth
        'name': name,
        'provider': 'email',
    }).execute()
    return response.data

engine = create_engine(SUPABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()