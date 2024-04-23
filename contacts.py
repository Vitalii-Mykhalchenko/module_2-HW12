from typing import List
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound
from sqlalchemy import and_

from models import Contact, ContactUpdate,User
from db import get_db, get_user_by_email
from fastapi import FastAPI, APIRouter
from typing import Optional, List
import bcrypt
from fastapi import APIRouter
from auth import *
# app = FastAPI()

app = APIRouter(prefix='/contacts', tags=['contacts'])


# @router.get("/")
# def read_main():
#     return {"message": "Hello World"}




@app.post("/create_contacts/")
def create_contact(first_name: str, last_name: str, email: str, phone_number: int, birthday: datetime, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    new_contact = Contact(first_name=first_name,
                          last_name=last_name, email=email, phone_number=phone_number, birthday=birthday, user_id=current_user.id)
    
    db.add(new_contact)
    db.commit()
    return new_contact


@app.get("/get_contacts/")
def get_contacts(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Contact).filter(Contact.user_id == current_user.id).all()


@app.get("/get_contact")
def get_contact(first_name=str, db: Session = Depends(get_db) , current_user: User = Depends(get_current_user)):
    contact = db.query(Contact).filter(and_(Contact.user_id == current_user.id,
        Contact.first_name == first_name)).first()
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


@app.put("/update_contact/")
def update_contact(
    contact_id: int,
    contact_update: ContactUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Найти контакт по идентификатору
    db_contact = db.query(Contact).filter(and_(Contact.user_id == current_user.id, Contact.id == contact_id)).first()
    if db_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")

    # Обновить свойства контакта на основе новых данных
    db_contact.first_name = contact_update.first_name
    db_contact.last_name = contact_update.last_name
    db_contact.email = contact_update.email
    db_contact.phone_number = contact_update.phone_number
    db_contact.birthday = contact_update.birthday
    db_contact.user_id = db_contact.user_id

    db.commit()
    db.refresh(db_contact)

    return db_contact


@app.delete("/delete_contact/")
def delete_contact(contact_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):

    db_contact = db.query(Contact).filter(and_(Contact.user_id == current_user.id, Contact.id == contact_id)).first()

    if db_contact is None:
            raise HTTPException(status_code=404, detail="Contact not found")

    db.delete(db_contact)
    db.commit()

    return {"message": "Contact deleted successfully"}


@app.get("/search_contacts/")
def search_contacts_by_name(
    first_name: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Поиск контактов по имени
    if first_name:
        db_contacts = db.query(Contact).filter(and_(Contact.user_id == current_user.id, 
            Contact.first_name.ilike(f"%{first_name}%"))).all()
    else:
        db_contacts = []

    return db_contacts










