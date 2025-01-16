from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# PostgreSQL connection URL
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:password@localhost:5433/taskdb"

# Create the SQLAlchemy engine
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Create a SessionLocal class for database sessions
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# Base class for declarative models
Base = declarative_base()