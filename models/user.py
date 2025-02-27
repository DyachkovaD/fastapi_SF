from sqlalchemy import String, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship

from .base import Base


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, autoincrement=True, primary_key=True, index=True)
    name = Column(String(256), unique=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(1024), nullable=False)
    salt = Column(String(1024), nullable=False, unique=True, index=True)
    role_id = Column(Integer, ForeignKey('role.id'))
    role = relationship("Role", back_populates="users")

    snippets = relationship("Snippet", back_populates="owner")