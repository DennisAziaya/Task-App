from fastapi import Depends, Form, Path, Query
from typing import Annotated, Optional
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session
from database import SessionLocal
from fastapi import HTTPException
from starlette import status
from fastapi import APIRouter
from models import User
from passlib.context import CryptContext

router = APIRouter()



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
    
db_dependency = Annotated[Session, Depends(get_db)]    


class CreateUserr(BaseModel):
    username: str
    email: str = Field(min_length=3, max_length=100)
    first_name: str
    last_name: str
    password: str
    role: str
    
    
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class OAuth2EmailOrUsernamePasswordRequestForm:
    def __init__(
        self,
        email_or_username: str = Form(..., description="Username or email"),
        password: str = Form(...),
    ):
        self.email_or_username = email_or_username
        self.password = password
    


def authenticate_user(email_or_username: str, password: str, db):
    # user = db.query(User).filter(User.email == email).first()
    user = db.query(User).filter((User.email == email_or_username) | (User.username == email_or_username)).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return True

        
@router.post("/login", status_code=status.HTTP_200_OK)
# async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
async def login(form_data: Annotated[OAuth2EmailOrUsernamePasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.email_or_username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    return {"message": "Succcess"}


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(db: db_dependency, create_user_request: CreateUserr):
    user = User(
        username=create_user_request.username,
        email=create_user_request.email,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        role=create_user_request.role,
        is_active=True,
        hashed_password=bcrypt_context.hash(create_user_request.password)
    )
    db.add(user)
    db.commit()
    return {"message": "User created successfully"}


