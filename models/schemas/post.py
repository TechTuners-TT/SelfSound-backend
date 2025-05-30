from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from enum import Enum


class PostType(str, Enum):
    media = "media"
    audio = "audio"
    note = "note"


class PostOut(BaseModel):
    id: UUID
    author_id: str
    description: Optional[str]
    post_type: PostType
    files: List[str]
    created_at: datetime
    author_name: Optional[str]
    author_login: Optional[str]
    author_avatar_url: Optional[str]
    like_count: int
