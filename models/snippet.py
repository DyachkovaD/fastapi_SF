import uuid
from datetime import datetime

from sqlalchemy import String, Column, Integer, TIMESTAMP, ForeignKey
from sqlalchemy.orm import relationship

from .base import Base


class Snippet(Base):
	__tablename__ = "snippet"
	id = Column(Integer, autoincrement=True, primary_key=True, index=True)
	text = Column(String(256), nullable=False)
	created_at = Column(TIMESTAMP, default=datetime.utcnow)
	owner_id = Column(Integer, ForeignKey("user.id"))
	owner = relationship("User", back_populates="snippets")

	share_id = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), index=True)