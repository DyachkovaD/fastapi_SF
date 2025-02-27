from sqlalchemy.future import select

from db.db import db_dependency
from models import Snippet, User


async def get_snippet_by_id(db: db_dependency, snippet_id: int):
	result = await db.execute(select(Snippet).filter(Snippet.id == snippet_id))
	return result.scalars().first()


async def get_snippet_by_share_id(db: db_dependency, share_id: str):
	result = await db.execute(select(Snippet).filter(Snippet.share_id == share_id))
	return result.scalars().first()


async def get_snippet_by_author(db: db_dependency, author: str):
	result = await db.execute(select(Snippet).join(Snippet.owner).filter(User.name == author))
	return result.scalars().all()


async def get_snippets(db: db_dependency, skip: int = 0, limit: int = 10):
	result = await db.execute(select(Snippet).offset(skip).limit(limit))
	return result.scalars().all()


async def create_snippet(db: db_dependency, text: str, owner: str):
	user = await db.execute(select(User).filter(User.email == owner.get("sub")))
	db_user = user.scalar_one_or_none()
	if db_user is None:
		raise ValueError("User not found")

	db_snippet = Snippet(text=text, owner=db_user)
	db.add(db_snippet)
	await db.commit()
	await db.refresh(db_snippet)
	return db_snippet

async def update_snippet(db: db_dependency, snippet_id: int, text: str):
	db_snippet = await get_snippet_by_id(db, snippet_id)
	if db_snippet:
		db_snippet.text = text
		await db.commit()
		await db.refresh(db_snippet)
	return db_snippet

async def delete_snippet(db: db_dependency, snippet_id: int):
	db_snippet = await get_snippet_by_id(db, snippet_id)
	if db_snippet:
		await db.delete(db_snippet)
		await db.commit()
	return db_snippet
