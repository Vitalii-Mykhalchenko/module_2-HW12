from sqlalchemy import Column, Integer, String, Boolean, func, Table, Date, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql.schema import ForeignKey
from sqlalchemy.sql.sqltypes import DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import date, timedelta
from pydantic import BaseModel


Base = declarative_base()


class Contact(Base):
    __tablename__ = "contacts"
    # Добавлено для решения проблемы
    __table_args__ = (
        UniqueConstraint('id', 'user_id', name='unique_tag_user'),
    )

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    email = Column(String, index=True)
    phone_number = Column(Integer, index=True)
    birthday = Column(Date)
    user_id = Column('user_id', ForeignKey(
        'users.id', ondelete='CASCADE'), default=None)
    user = relationship('User', backref="contacts")

class ContactUpdate(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone_number: int
    birthday: date


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50))
    email = Column(String(250), nullable=False, unique=True)
    password = Column(String(255), nullable=False)
    created_at = Column('created_at', DateTime, default=func.now())
    avatar = Column(String(255), nullable=True)
    refresh_token = Column(String(255), nullable=True)



class UserCreate(BaseModel):
    username: str
    email: str
    password: str
