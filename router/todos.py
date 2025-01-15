from fastapi import Depends, Path, Query
from typing import Annotated, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from models import Todo
from database import SessionLocal
from fastapi import HTTPException
from starlette import status
from fastapi import APIRouter


router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
    
db_dependency = Annotated[Session, Depends(get_db)]    



class TodoRequest(BaseModel):
    title: str = Field(min_length=3, max_length=100)
    description: str = Field(min_length=3, max_length=256)
    completed: bool
    priority: int = Field(gt=0, lt=20)
    
    

        
@router.get("/", status_code=status.HTTP_200_OK)
async def get_todos(db: db_dependency):
    objs = db.query(Todo).all()
    return objs



@router.get("/todo/{id}", status_code=status.HTTP_200_OK)
async def todo(db: db_dependency, id : int = Path(gt=0)):
    obj = db.query(Todo).filter(Todo.id == id).first()
    if obj is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    return obj


@router.get("/todo/")
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

@router.post("/todo", status_code=status.HTTP_201_CREATED)
async def create_todo(db: db_dependency, todo_request: TodoRequest):
    todo = Todo(**todo_request.model_dump())
    db.add(todo)
    db.commit()
    # db.refresh(todo)
    # return todo
    
    
@router.put("/todo/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def update_todo(db: db_dependency, todo_request: TodoRequest, id: int = Path(gt=0)):
    todo = db.query(Todo).filter(Todo.id == id).first()
    if todo is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    todo.title = todo_request.title
    todo.description = todo_request.description
    todo.completed = todo_request.completed
    todo.priority = todo_request.priority
    db.add(todo)
    db.commit()
    
    
    
@router.delete("/todo/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_todo(db: db_dependency, id: int = Path(gt=0)):
    todo = db.query(Todo).filter(Todo.id == id).first()
    if todo is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    db.delete(todo)
    db.commit()
    
    
    


