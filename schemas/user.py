from pydantic import BaseModel, EmailStr
from typing import Optional

class User(BaseModel):
    name: str
    email: EmailStr
    age: Optional[int] = None

class UserRegisterSchema(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str