from pydantic import BaseModel
from uuid import UUID
from typing import Optional
from datetime import datetime


class CommentCreate(BaseModel):
    content: str

class CommentOut(BaseModel):
    id: UUID
    post_id: UUID
    author_id: str
    content: str
    created_at: datetime
    author_name: Optional[str]
    author_login: Optional[str]
    author_avatar_url: Optional[str]
    like_count: int

class LikeResponse(BaseModel):
        detail: str

class LikeCount(BaseModel):
        likes: int