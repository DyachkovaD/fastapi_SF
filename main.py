from fastapi import FastAPI, APIRouter, Request, HTTPException
import uvicorn
from sqlalchemy import select
from starlette.responses import JSONResponse

from api.snippets import snippets_router
from api.user import user_router
from core.config import uvicorn_options
from db.db import db_dependency, async_session
from models import Role
from models.role import RoleEnum
import logging.config
import logging.handlers
import atexit
from contextlib import asynccontextmanager
from typing import AsyncContextManager

from core.logger import LOGGING_CONFIG



# @asynccontextmanager
# async def lifespan(app: FastAPI) -> AsyncContextManager[None]:
#     logging.config.dictConfig(LOGGING_CONFIG)
#     # получаем обработчик очереди из корневого логгера
#     queue_handler = logging.getHandlerByName("queue_handler")
#     try:
#         # если логгер есть
#         if queue_handler is not None:
#             # запускаем слушатель очереди
#             queue_handler.listener.start()
#             # регистрируем функцию, которая будет вызвана при завершении работы программы
#             atexit.register(queue_handler.listener.stop)
#         yield
#     finally:
#         # в случае ошибки выключаем слушатель
#         if queue_handler is not None:
#             queue_handler.listener.stop()


app = FastAPI(
    # lifespan=lifespan,
    docs_url="/api"
)

logger = logging.getLogger("my_app")

router = APIRouter()

app.include_router(router)
app.include_router(user_router)
app.include_router(snippets_router)


async def ensure_roles_exist(db: db_dependency):
    user_role = await db.execute(select(Role).filter_by(name=RoleEnum.USER))
    user_role = user_role.scalars().first()
    if not user_role:
        user_role = Role(name=RoleEnum.USER)
        db.add(user_role)
        await db.commit()
        await db.refresh(user_role)

    admin_role = await db.execute(select(Role).filter_by(name=RoleEnum.ADMIN))
    admin_role = admin_role.scalars().first()
    if not admin_role:
        admin_role = Role(name=RoleEnum.ADMIN)
        db.add(admin_role)
        await db.commit()
        await db.refresh(admin_role)


@app.middleware("http")
async def lifespan_middleware(request: Request, call_next):
    async with async_session() as db:
        await ensure_roles_exist(db)
        response = await call_next(request)
    return response

@app.middleware("http")
async def error_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"message": exc.detail}
        )
    except Exception as e:
        logger.error(f"{request.url} | Error in application: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Internal server error"}
        )

if __name__ == '__main__':
    uvicorn.run(
        'main:app',
        **uvicorn_options
    )