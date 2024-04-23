from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import User
from sqlalchemy.orm import Session
from fastapi import HTTPException, status


SQLALCHEMY_DATABASE_URL = "postgresql://postgres:567234@localhost:5433/postgres"
engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).one_or_none()


