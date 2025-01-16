from datetime import datetime, timedelta, timezone
import re
from email_validator import validate_email, EmailNotValidError
from fastapi import Depends, Form, Path, Query
from typing import Annotated, Optional, Union
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import or_
from sqlalchemy.orm import Session
from database import SessionLocal
from fastapi import HTTPException
from starlette import status
from fastapi import APIRouter
from models import Todo, User
from passlib.context import CryptContext
from jose import JWTError, jwt

from router.auth import get_current_user

router = APIRouter()
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]    
user_dependency = Annotated[dict, Depends(get_current_user)]


@router.get("/todos", status_code=status.HTTP_200_OK)
async def todo(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    
    if user.get("role") != "admin":
        raise HTTPException(status_code=401, detail="You are not allowed to perform this action")
    # return db.query(Todo).filter(Todo.owner_id == user.get("id")).all()
    return db.query(Todo).all()