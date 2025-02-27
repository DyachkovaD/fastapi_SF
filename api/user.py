import httpx
from fastapi import APIRouter, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from starlette import status

from core.config import create_access_token, oauth2_bearer, JWT_SECRET, ALGORITHM
from db.db import db_dependency
from models import Role
from models.role import RoleEnum
from schemas.user import UserRegisterSchema, UserLoginSchema
from services.user import *

user_router = APIRouter(prefix="/user", tags=['user'])

@user_router.post("/register")
async def register_user(user_data: UserRegisterSchema, db: db_dependency):
    try:
        return await reg_user(user_data=user_data, db=db)
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Аn error has occurred: {ex}")


@user_router.post("/login")
async def login_for_access_token(db: db_dependency,
                                 login_data: UserLoginSchema):
    user = await authenticate_user(login_data, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": {"email": user.email, "role": user.role.name.value}}
    )
    return {"access_token": access_token, "token_type": "bearer"}


@user_router.post("/token")
async def token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                db: db_dependency):
    user = await authenticate_user(
        UserLoginSchema(email=form_data.username, password=form_data.password), db=db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not validate user.")
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role.name.value}
    )
    return {'access_token': access_token, 'token_type': 'bearer'}


@user_router.get("/current_user")
async def get_current_user(user: user_dependency):
    return {"user": user}


