import httpx
from fastapi import APIRouter, HTTPException, Depends
from db.db import db_dependency
from models import User
from services.snippet import *

from schemas.snippet import Snippets, SnippetCreate, SnippetUpdate, ShareSnippetResponse
from services.user import has_role, get_current_user

snippets_router = APIRouter(prefix="/snippets", tags=["snippets"])

@snippets_router.get("/{snippet_id}")
async def read_snippet(snippet_id: int, db: db_dependency, current_user: User = Depends(get_current_user)):
    snippet = await get_snippet_by_id(db, snippet_id)
    if snippet is None:
        raise HTTPException(status_code=404, detail="Snippet not found")
    return snippet

@snippets_router.get("/author/{author}")
async def read_snippets_by_author(author: str, db: db_dependency):
    snippets = await get_snippet_by_author(db, author)
    if not snippets:
        raise HTTPException(status_code=404, detail="No snippets found for this author")
    return snippets

@snippets_router.get("/")
async def read_snippets(db: db_dependency, skip: int = 0, limit: int = 10, current_user: User = Depends(get_current_user)):
    snippets = await get_snippets(db, skip, limit)
    return snippets

@snippets_router.post("/")
async def create_snippet_route(snippet: SnippetCreate, db: db_dependency, current_user: User = Depends(get_current_user)):
    return await create_snippet(db, snippet.text, current_user)

@snippets_router.put("/{snippet_id}")
async def update_snippet_route(snippet_id: int, snippet: SnippetUpdate, db: db_dependency, current_user: User = Depends(get_current_user)):
    updated_snippet = await update_snippet(db, snippet_id, snippet.text)
    if updated_snippet is None:
        raise HTTPException(status_code=404, detail="Snippet not found")
    return updated_snippet

@snippets_router.delete("/{snippet_id}",
                        dependencies=[Depends(has_role(["admin"]))])
async def delete_snippet_route(snippet_id: int, db: db_dependency):
    deleted_snippet = await delete_snippet(db, snippet_id)
    if deleted_snippet is None:
        raise HTTPException(status_code=404, detail="Snippet not found")
    return deleted_snippet

@snippets_router.post("/{snippet_id}/share")
async def share_snippet(snippet_id: int, db: db_dependency):
    snippet = await get_snippet_by_id(db, snippet_id)
    if not snippet:
        raise HTTPException(status_code=404, detail="Snippet not found")
    return {"share_url": f"/share/{snippet.share_id}"}

@snippets_router.get("/share/{share_id}", response_model=Snippets)
async def get_shared_snippet(share_id: str, db: db_dependency):
    snippet = await get_snippet_by_share_id(db, share_id)
    if not snippet:
        raise HTTPException(status_code=404, detail="Snippet not found")
    return snippet