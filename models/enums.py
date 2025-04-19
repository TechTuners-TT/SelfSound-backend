from enum import Enum

class PostType(str, Enum):
    MEDIA = "media"
    AUDIO = "audio"
    NOTE = "note"
