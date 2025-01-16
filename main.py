from fastapi import FastAPI, Depends, Path, Query
from typing import Annotated, Optional
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session
import models
from models import Todo
from database import engine, SessionLocal
from fastapi import HTTPException
from starlette import status

from router import auth, todos, admin, users


app = FastAPI()


models.Base.metadata.create_all(engine)

app.include_router(todos.router, prefix="/todos", tags=["Todos"])
app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])
app.include_router(users.router, prefix="/users", tags=["Users"])

