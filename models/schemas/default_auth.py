from pydantic import BaseModel, EmailStr
from typing import Optional

class SignupRequest(BaseModel):
    email: str
    password: str
    name: str
    picture: Optional[str] = None

class LoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str

class UserCreate(BaseModel):
    email: str
    password: str
    name: str = None


class UserInDB(BaseModel):
    email: str
    name: str
    provider: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str