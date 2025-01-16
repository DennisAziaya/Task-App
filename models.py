from database import Base
from sqlalchemy import Integer, Column, String, Boolean 
from sqlalchemy import ForeignKey


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(256), unique=True)
    username = Column(String(256), unique=True)
    first_name = Column(String(256))
    last_name = Column(String(256))
    hashed_password = Column(String)
    is_active = Column(Boolean, default=False)
    role = Column(String(256))


class Todo(Base):
    __tablename__ = "todos"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(256))
    description = Column(String(256))
    completed = Column(Boolean, default=False)
    priority = Column(Integer)
    owner_id = Column(Integer, ForeignKey("users.id"))
    
    
    
# [
#   {
    # "description": "Milk, Bread, Eggs",
    # "id": 2,
    # "title": "Buy Groceries",
    # "completed": false,
    # "priority": 1
#   },
#   {
#     "description": "Vacuum and mop floors",
#     "id": 3,
#     "title": "Clean the House",
#     "completed": false,
#     "priority": 5
#   },
#   {
#     "description": "Slides for Monday meeting",
#     "id": 4,
#     "title": "Prepare Presentation",
#     "completed": false,
#     "priority": 3
#   },
#   {
#     "description": "Wash dogs and cats",
#     "id": 5,
#     "title": "Clean Pet",
#     "completed": false,
#     "priority": 4
#   },
#   {
#     "description": "Milk, bread, eggs, sugar, and coffee",
#     "id": 6,
#     "title": "Buy all groceries",
#     "completed": false,
#     "priority": 10
#   }
# ]