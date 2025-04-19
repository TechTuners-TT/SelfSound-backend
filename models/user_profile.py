# schemas/user_profile.py
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional
from uuid import UUID

# Schema for creating/updating a user profile
class UserProfileCreate(BaseModel):
    name: str
    login: str  # extracted from Gmail
    avatar_url: Optional[HttpUrl] = None

# Schema for reading/displaying user profile
class UserProfileResponse(BaseModel):
    id: UUID
    name: str
    login: str
    avatar_url: Optional[HttpUrl]

    class Config:
        orm_mode = True
