from datetime import datetime

from pydantic import BaseModel

class Snippets(BaseModel):
    id: int
    created_at: datetime
    text: str
    owner_id: int

class SnippetCreate(BaseModel):
    text: str

class SnippetUpdate(BaseModel):
    text: str

class ShareSnippetResponse(BaseModel):
    share_url: str