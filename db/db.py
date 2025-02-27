from fastapi import Depends
from sqlalchemy.ext.asyncio import (async_sessionmaker,
									create_async_engine,
									AsyncSession, AsyncEngine, AsyncConnection)

from core.config import app_settings
from typing import Union, Callable, Annotated, Type


class InternalError(Exception):
	pass

# Функция get_async_session используется для получения асинхронной сессии SQLAlchemy
async def get_async_session() -> AsyncSession:
	async with async_session() as session:
		try:
			yield session
		except InternalError:
			# в случае ошибки будет произведён откат транзакции
			await session.rollback()

# Функция create_sessionmaker создаёт фабрику сессий для асинхронной работы с базой данных
def create_sessionmaker(
		bind_engine: Union[AsyncEngine, AsyncConnection]
) -> Callable[..., async_sessionmaker]:
	# Возвращается фабрика сессий, определённая с заданными параметрами
	return async_sessionmaker(
		bind=bind_engine,
		expire_on_commit=False,
		class_=AsyncSession,
	)

# Создание асинхронного движка SQLAlchemy для работы с PostgreSQL
engine = create_async_engine(app_settings.postgres_dsn.unicode_string())

# Создание фабрики для сессий
async_session = create_sessionmaker(engine)

# Создание зависимости для работы с базой данных
db_dependency: Type[AsyncSession] = Annotated[AsyncSession, Depends(get_async_session)]