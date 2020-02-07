from .dbclasses import Base
from sqlalchemy import create_engine
import os

def _get_db_URL():
    db_URL = os.environ.get('DATABASE_URL', '')
    return db_URL

def create_tables():
    db_URL = _get_db_URL()
    if not db_URL:
        raise Exception('DATABASE_URL environment variable is not defined')

    engine = create_engine(db_URL, echo=True)
    Base.metadata.create_all(engine)

def drop_tables():
    db_URL = _get_db_URL()
    if not db_URL:
        raise Exception('DATABASE_URL environment variable is not defined')

    engine = create_engine(db_URL, echo=True)
    Base.metadata.drop_all(engine)
