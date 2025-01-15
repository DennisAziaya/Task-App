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

from router import auth, todos


app = FastAPI()

models.Base.metadata.create_all(engine)

app.include_router(todos.router, prefix="/todos", tags=["todos"])
app.include_router(auth.router, prefix="/auth", tags=["auth"])

