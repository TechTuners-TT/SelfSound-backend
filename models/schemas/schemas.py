from pydantic import BaseModel, EmailStr
from typing import Optional
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name:str

class UserInDB(UserCreate):
    id: int

    class Config:
        orm_mode = True

class UserSignIn(BaseModel):
    email: EmailStr
    password: str

from pydantic import BaseModel


class PublicUserProfile(BaseModel):
    id: str
    name: str
    login: str
    avatar_url: Optional[str]
