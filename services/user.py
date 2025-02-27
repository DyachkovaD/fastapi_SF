from calendar import timegm
from datetime import timedelta, datetime
from typing import Optional, Annotated, Dict, List

import bcrypt
from asyncpg import UniqueViolationError
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from starlette import status

from core.config import app_settings, generate_salt, hash_password, bcrypt_context, oauth2_bearer, JWT_SECRET, ALGORITHM
from db.db import db_dependency
from models import User, Role
from models.role import RoleEnum
from schemas.user import UserRegisterSchema, UserLoginSchema


# Регистрация пользователя
async def reg_user(user_data: UserRegisterSchema, db: db_dependency):
    user_salt: str = generate_salt()
    user_role = await db.execute(select(Role).filter_by(name=RoleEnum.USER))
    user_role = user_role.scalars().first()

    try:
        create_user_statement: User = User(
            **user_data.model_dump(exclude={'password'}),  # распаковываем объект пользователя, исключая пароль
            salt=user_salt,
            hashed_password=hash_password(user_data.password, user_salt),
            role=user_role,
        )
        # создаём пользователя в базе данных
        db.add(create_user_statement)
        await db.commit()
        return {"response": "User created successfully"}
    except UniqueViolationError:
        # если возникает ошибка UniqueViolationError, то считаем, что пользователь с такими данными уже есть
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='User with such credentials already exists')
    except Exception as ex:
        raise ex


# Аутентификация пользователя
async def authenticate_user(login_data: UserLoginSchema, db: db_dependency):
    # делаем SELECT-запрос в базу данных для нахождения пользователя по email
    result = await db.execute(select(User)
                              .options(joinedload(User.role))
                              .where(User.email == login_data.email))
    user: Optional[User] = result.scalars().first()
    # пользователь будет авторизован, если он зарегистрирован и ввёл корректный пароль
    if not user:
        return False
    if not bcrypt_context.verify(login_data.password + user.salt, user.hashed_password):
        return False
    return user


# Получение текущего пользователя
async def get_current_user(token: str = Depends(oauth2_bearer)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_data = {"sub": payload.get("sub"), "role": payload.get("role")}
        if user_data is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user_data

user_dependency = Annotated[Dict, Depends(get_current_user)]


def has_role(required_role: List[str]):
    def role_checker(current_user: user_dependency):
        if current_user["role"] not in required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    return role_checker