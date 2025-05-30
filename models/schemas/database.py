from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from supabase_client import SUPABASE_URL

engine = create_engine(SUPABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
