# from datetime import datetime, timedelta, timezone
# import re
# from email_validator import validate_email, EmailNotValidError
# from fastapi import Depends, Form, Path, Query
# from typing import Annotated, Optional, Union
# from fastapi.security import OAuth2PasswordBearer
# from pydantic import BaseModel, EmailStr, Field, field_validator
# from sqlalchemy import or_
# from sqlalchemy.orm import Session
# from database import SessionLocal
# from fastapi import HTTPException
# from starlette import status
# from fastapi import APIRouter
# from models import User
# from passlib.context import CryptContext
# from jose import JWTError, jwt

# from router.auth import get_current_user

# router = APIRouter()

# SECRET_KEY = "6cbe0b670af08c878039fc387a53d3273b07aca49d1855557fd27b1502dcd154"
# ALGORITHM = "HS256"
# DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
# oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/auth/login")

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()


# db_dependency = Annotated[Session, Depends(get_db)]  
# user_dependency = Annotated[dict, Depends(get_current_user)]
# bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto") 

# class UserProfileDetails(BaseModel):
#     id: int
#     first_name: str = Field(min_length=1, max_length=50)
#     last_name: str = Field(min_length=1, max_length=50)
#     email: EmailStr
#     username: str = Field(min_length=1, max_length=50)
#     role: str = Field(min_length=1, max_length=50)
    
    
# class UpdateUser(BaseModel):
#     username: Optional[str] = None
#     email: Optional[str] = None
#     first_name: Optional[str] = None
#     last_name: Optional[str] = None
#     password: Optional[str] = None
#     role: Optional[str] = None
#     # username: str
#     # email: str = Field(min_length=3, max_length=100)
#     # first_name: str
#     # last_name: str
#     # password: str
#     # role: str
    
#     # Password validation
#     @field_validator('password')
#     def validate_password(cls, password):
#         # Minimum length of 8 characters
#         if len(password) < 8:
#             raise ValueError("Password must be at least 8 characters long")
        
#         # At least one uppercase letter
#         if not re.search(r'[A-Z]', password):
#             raise ValueError("Password must contain at least one uppercase letter")
        
#         # At least one lowercase letter
#         if not re.search(r'[a-z]', password):
#             raise ValueError("Password must contain at least one lowercase letter")
        
#         # At least one digit
#         if not re.search(r'\d', password):
#             raise ValueError("Password must contain at least one number")
        
#         # At least one special character
#         if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
#             raise ValueError("Password must contain at least one special character")
        
#         return password

#     @field_validator('username')
#     def validate_username(cls, username):
#         # Username should be alphanumeric
#         if not username.isalnum():
#             raise ValueError("Username must contain only letters and numbers")
#         return username
    
#     @field_validator('email')
#     def validate_email(cls, email):
#         # Common email patterns to reject
#         disposable_domains = [
#             'tempmail.com', 'throwawaymail.com', 'temp-mail.org', 'fakeinbox.com',
#             'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'temp-mail.io',
#             'trashmail.com', 'yopmail.com', 'getnada.com', 'dispostable.com',
#             'maildrop.cc', 'moakt.com', 'mytemp.email', 'spambog.com',
#             'emailondeck.com', 'mintemail.com', 'mailcatch.com', 'eyepaste.com',
#             'inboxbear.com', 'instantemailaddress.com', 'jetable.org', 'spamgourmet.com',
#             'mail-temp.com', 'anonbox.net', 'mailbox52.com', 'easytrashmail.com',
#             'temporaryemail.net', 'tempail.com', 'mailnesia.com', 'onetime.email',
#             'fakemail.net', 'mailtothis.com', 'mailprotech.com', 'freeml.net'
#         ]

#         # Basic format validation
#         pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
#         if not re.match(pattern, email):
#             raise ValueError("Invalid email format")

#         # Check for disposable email domains
#         domain = email.split('@')[1].lower()
#         if domain in disposable_domains:
#             raise ValueError("Disposable email addresses are not allowed")

#         # Advanced validation using email-validator library
#         try:
#             # The validation function returns a normalized email address
#             validated_email = validate_email(email, check_deliverability=False)
#             return validated_email.normalized
#         except EmailNotValidError as e:
#             raise ValueError(str(e))
    



# @router.get("/profile", status_code=status.HTTP_200_OK, response_model=UserProfileDetails)
# async def get_user(user: user_dependency, db: db_dependency):
#     if user is None:
#         raise HTTPException(status_code=401, detail="Authentication Failed")
#     return db.query(User).filter(User.id == user.get("id")).first()


# @router.put("/update-profile", status_code=status.HTTP_202_ACCEPTED)
# async def update_user(
#     user: user_dependency,
#     db: db_dependency,
#     request_data : UpdateUser
# ):
#     if user is None:
#         raise HTTPException(status_code=401, detail="Authentication Failed")
    
#     # Fetch the user from the database
#     user_model = db.query(User).filter(User.id == user.get("id")).first()
#     if user_model is None:
#         raise HTTPException(status_code=404, detail="User not found")
    
#     # Check if the new email is already in use by another user
#     existing_user = db.query(User).filter(User.email == request_data.email).first()
#     if existing_user and existing_user.id != user_model.id:
#         raise HTTPException(status_code=400, detail="Email already in use by another user")
    
#     # Check if the new username is already in use by another user
#     existing_user = db.query(User).filter(User.username == request_data.username).first()
#     if existing_user and existing_user.id != user_model.id:
#         raise HTTPException(status_code=400, detail="Username already in use by another user")
    
    
#     # Check if the new password is the same as the current password
#     if bcrypt_context.verify(request_data.password, user_model.hashed_password):
#         raise HTTPException(
#             status_code=400,
#             detail="New password cannot be the same as the current password"
#         )
    
    
#     # Update the user's information
#     user_model.first_name = request_data.first_name
#     user_model.last_name = request_data.last_name
#     user_model.email = request_data.email
#     user_model.username = request_data.username
#     user_model.role = request_data.role
    
#     # Hash the new password
#     hashed_password = bcrypt_context.hash(request_data.password)
#     user_model.hashed_password = hashed_password
    
#     db.add(user_model)
#     db.commit()
    
#     return {"detail": "User updated successfully"}



from datetime import datetime, timedelta, timezone
import re
from email_validator import validate_email, EmailNotValidError
from fastapi import Depends, Form, Path, Query
from typing import Annotated, Optional, Union
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import or_
from sqlalchemy.orm import Session
from database import SessionLocal
from fastapi import HTTPException
from starlette import status
from fastapi import APIRouter
from models import User
from passlib.context import CryptContext
from jose import JWTError, jwt

from router.auth import get_current_user

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
user_dependency = Annotated[dict, Depends(get_current_user)]
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto") 

class UserProfileDetails(BaseModel):
    id: int
    first_name: str = Field(min_length=1, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    email: EmailStr
    username: str = Field(min_length=1, max_length=50)
    role: str = Field(min_length=1, max_length=50)
    
class UpdateUserInfo(BaseModel):
    username: Optional[str] = Field(default=None, min_length=1, max_length=50)
    email: Optional[str] = Field(default=None, min_length=3, max_length=100)
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    role: Optional[str] = Field(default=None, min_length=1, max_length=50)
    

    @field_validator('username')
    def validate_username(cls, username):
        if username is None:
            return username  # Skip validation if username is not provided
        
        # Username should be alphanumeric
        if not username.isalnum():
            raise ValueError("Username must contain only letters and numbers")
        return username
    
    @field_validator('email')
    def validate_email(cls, email):
        if email is None:
            return email  # Skip validation if email is not provided
        
        # Common email patterns to reject
        disposable_domains = [
            'tempmail.com', 'throwawaymail.com', 'temp-mail.org', 'fakeinbox.com',
            'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'temp-mail.io',
            'trashmail.com', 'yopmail.com', 'getnada.com', 'dispostable.com',
            'maildrop.cc', 'moakt.com', 'mytemp.email', 'spambog.com',
            'emailondeck.com', 'mintemail.com', 'mailcatch.com', 'eyepaste.com',
            'inboxbear.com', 'instantemailaddress.com', 'jetable.org', 'spamgourmet.com',
            'mail-temp.com', 'anonbox.net', 'mailbox52.com', 'easytrashmail.com',
            'temporaryemail.net', 'tempail.com', 'mailnesia.com', 'onetime.email',
            'fakemail.net', 'mailtothis.com', 'mailprotech.com', 'freeml.net'
        ]

        # Basic format validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            raise ValueError("Invalid email format")

        # Check for disposable email domains
        domain = email.split('@')[1].lower()
        if domain in disposable_domains:
            raise ValueError("Disposable email addresses are not allowed")

        # Advanced validation using email-validator library
        try:
            # The validation function returns a normalized email address
            validated_email = validate_email(email, check_deliverability=False)
            return validated_email.normalized
        except EmailNotValidError as e:
            raise ValueError(str(e))


class UpdateUserPassword(BaseModel):
    old_password: str = Field(min_length=8, max_length=50)
    new_password: str = Field(min_length=8, max_length=50)
    confirm_password: str = Field(min_length=8, max_length=50)
    
    # Validate the new password
    @field_validator('new_password')
    def validate_new_password(cls, new_password):
        # Minimum length of 8 characters
        if len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # At least one uppercase letter
        if not re.search(r'[A-Z]', new_password):
            raise ValueError("Password must contain at least one uppercase letter")
        
        # At least one lowercase letter
        if not re.search(r'[a-z]', new_password):
            raise ValueError("Password must contain at least one lowercase letter")
        
        # At least one digit
        if not re.search(r'\d', new_password):
            raise ValueError("Password must contain at least one number")
        
        # At least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            raise ValueError("Password must contain at least one special character")
        
        return new_password
    
    # Ensure new_password and confirm_password match
    @field_validator('confirm_password')
    def validate_confirm_password(cls, confirm_password, values):
        if 'new_password' in values.data and confirm_password != values.data['new_password']:
            raise ValueError("New password and confirm password do not match")
        return confirm_password


@router.get("/profile", status_code=status.HTTP_200_OK, response_model=UserProfileDetails)
async def get_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    return db.query(User).filter(User.id == user.get("id")).first()


@router.put("/update-profile", status_code=status.HTTP_202_ACCEPTED)
async def update_user(
    user: user_dependency,
    db: db_dependency,
    request_data: UpdateUserInfo
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    
    # Fetch the user from the database
    user_model = db.query(User).filter(User.id == user.get("id")).first()
    if user_model is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update only the fields that are provided
    if request_data.first_name is not None:
        user_model.first_name = request_data.first_name
    
    if request_data.last_name is not None:
        user_model.last_name = request_data.last_name
    
    if request_data.email is not None:
        # Check if the new email is already in use by another user
        existing_user = db.query(User).filter(User.email == request_data.email).first()
        if existing_user and existing_user.id != user_model.id:
            raise HTTPException(status_code=400, detail="Email already in use by another user")
        user_model.email = request_data.email
    
    if request_data.username is not None:
        # Check if the new username is already in use by another user
        existing_user = db.query(User).filter(User.username == request_data.username).first()
        if existing_user and existing_user.id != user_model.id:
            raise HTTPException(status_code=400, detail="Username already in use by another user")
        user_model.username = request_data.username
    
    if request_data.role is not None:
        user_model.role = request_data.role
   
    db.add(user_model)
    db.commit()
    
    return {"detail": "User updated successfully"}





@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    user: user_dependency,
    db: db_dependency,
    password_data: UpdateUserPassword
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    
    # Fetch the user from the database
    user_model = db.query(User).filter(User.id == user.get("id")).first()
    if user_model is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify the old password
    if not bcrypt_context.verify(password_data.old_password, user_model.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Old password is incorrect"
        )
    
    # Check if the new password is the same as the old password
    if bcrypt_context.verify(password_data.new_password, user_model.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Please enter a password that you've never used before"
        )
    
    # Hash the new password
    hashed_password = bcrypt_context.hash(password_data.new_password)
    user_model.hashed_password = hashed_password
    
    db.add(user_model)
    db.commit()
    
    return {"detail": "Password updated successfully"}