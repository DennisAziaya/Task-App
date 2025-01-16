from fastapi import Depends, Path, Query
from typing import Annotated, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from models import Todo
from database import SessionLocal
from fastapi import HTTPException
from starlette import status
from fastapi import APIRouter

from router.auth import get_current_user


router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
    
db_dependency = Annotated[Session, Depends(get_db)]    
user_dependency = Annotated[dict, Depends(get_current_user)]



class TodoRequest(BaseModel):
    title: str = Field(min_length=3, max_length=100)
    description: str = Field(min_length=3, max_length=256)
    completed: bool
    priority: int = Field(gt=0, lt=20)
    
    

        
@router.get("/list", status_code=status.HTTP_200_OK)
async def get_todos(db: db_dependency):
    objs = db.query(Todo).all()
    return objs



@router.get("/detail/{id}", status_code=status.HTTP_200_OK)
async def todo(db: db_dependency, id : int = Path(gt=0)):
    obj = db.query(Todo).filter(Todo.id == id).first()
    if obj is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    return obj


@router.get("/search/")
async def query_todos(
   db: db_dependency,
   title: Optional[str] = Query(default=None),
   completed: Optional[bool] = Query(default=None),
   priority: Optional[int] = Query(default=None, gt=0)
):
   query = db.query(Todo)
   
   if title:
       query = query.filter(Todo.title.ilike(f"%{title}%"))
   if completed is not None:
       query = query.filter(Todo.completed == completed)
   if priority:
       query = query.filter(Todo.priority == priority)
   
   todos = query.all()
   if not todos:
       raise HTTPException(status_code=404, detail="No todos found")
   return todos

@router.post("/add", status_code=status.HTTP_201_CREATED)
async def create_todo(user: user_dependency, db: db_dependency, todo_request: TodoRequest):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    todo = Todo(**todo_request.model_dump(), owner_id=user.get("id"))
    db.add(todo)
    db.commit()



@router.put("/update/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def update_todo(
    user: user_dependency,
    db: db_dependency,
    todo_request: TodoRequest,
    id: int = Path(gt=0),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    
    # Fetch the todo from the database
    todo = db.query(Todo).filter(Todo.id == id).first()
    if todo is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    
    # Check if the authenticated user is the owner of the todo
    if todo.owner_id != user.get("id"):
        raise HTTPException(status_code=403, detail="You are not authorized to update this todo")
    
    # Update the todo fields
    todo.title = todo_request.title
    todo.description = todo_request.description
    todo.completed = todo_request.completed
    todo.priority = todo_request.priority
    
    # Save changes to the database
    db.add(todo)
    db.commit()
    
    
    
@router.delete("/delete/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_todo(
    user: user_dependency,
    db: db_dependency,
    id: int = Path(gt=0),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    
    # Fetch the todo from the database
    todo = db.query(Todo).filter(Todo.id == id).first()
    if todo is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    
    # Check if the authenticated user is the owner of the todo
    if todo.owner_id != user.get("id"):
        raise HTTPException(status_code=403, detail="You are not authorized to delete this todo")
    
    # Delete the todo
    db.delete(todo)
    db.commit()
    
    
    
@router.get("/user", status_code=status.HTTP_200_OK)
async def read_all_by_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    user_todos = db.query(Todo).filter(Todo.owner_id == user.get("id")).all()
    return user_todos
    
    


