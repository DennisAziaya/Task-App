from datetime import datetime, timedelta, timezone
from fastapi import Depends, Form, Path, Query
from typing import Annotated, Optional, Union
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session
from database import SessionLocal
from fastapi import HTTPException
from starlette import status
from fastapi import APIRouter
from models import User
from passlib.context import CryptContext
from jose import JWTError, jwt

router = APIRouter()

SECRET_KEY = "6cbe0b670af08c878039fc387a53d3273b07aca49d1855557fd27b1502dcd154"
ALGORITHM = "HS256"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/auth/login")

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
    
    
class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    role: str
    
    
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def authenticate_user(username: str, password: str, db):
    user = db.query(User).filter((User.email == username) | (User.username == username)).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user



def create_access_token(username: str, user_id: int,
                        expires_delta: Optional[Union[timedelta, None]] = None):
    
    encode = {"sub": username, "id": user_id}
    
    # Set the expiration time
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # Use default expiration time if expires_delta is not provided
        expire = datetime.now(timezone.utc) + timedelta(minutes=DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Add expiration to the payload
    encode.update({"exp": expire})
    
    # Generate the JWT token
    token = jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)
    return token


def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user")
        return {"username": username, "id": user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user")

        
@router.post("/login", response_model=Token, status_code=status.HTTP_200_OK)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    token = create_access_token(form_data.username, user.id, timedelta(minutes=30))
    return {"user_id": user.id, "role": user.role, "access_token": token, "token_type": "bearer"}


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


