from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=True)
    picture = Column(String, nullable=True)
    sub = Column(String, nullable=True)  # Only for Google OAuth users
    provider = Column(String, nullable=False, default="email")  # "email" or "google"
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    hashed_password = Column(String, nullable=True)  # For email/password registration
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)
