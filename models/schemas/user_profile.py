from pydantic import BaseModel, HttpUrl, Field, EmailStr
from uuid import UUID
from typing import Optional, Union


# Схема для створення/оновлення профілю користувача
class UserProfileCreate(BaseModel):
    name: str
    login: str  # логін, наприклад, із Gmail
    avatar_url: Optional[HttpUrl] = None


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=50)
    login: Optional[str] = Field(None, min_length=3, max_length=30)
    description: Optional[str] = Field(None, max_length=160)
    tag_id: Optional[Union[UUID, str]] = None



# Схема відповіді з даними профілю користувача
class UserProfileResponse(BaseModel):
    id: UUID  # або UUID, якщо у вас UUID
    name: str
    login: str
    avatar_url: Optional[HttpUrl] = None
    description: Optional[str] = None
    tag_id: Optional[UUID] = None

    class Config:
        orm_mode = True

class UpdateDescriptionRequest(BaseModel):
        description: str

class UserOut(UserProfileResponse):
    email: EmailStr
    provider: Optional[str] = None
