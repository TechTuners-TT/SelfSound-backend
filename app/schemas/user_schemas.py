# app/schemas/user_schemas.py

from pydantic import BaseModel
from typing import Optional

class User(BaseModel):
    id: int
    username: str
    email: str

