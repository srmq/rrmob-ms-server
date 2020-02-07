from .dbclasses import Base, User, Invitee
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import os
from contextlib import contextmanager

def _get_db_URL():
    db_URL = os.environ.get('DATABASE_URL', '')
    return db_URL

def _get_db_engine():
    db_URL = _get_db_URL()
    if not db_URL:
        raise Exception('DATABASE_URL environment variable is not defined')

    return create_engine(db_URL, echo=True)

engine = _get_db_engine()
Session = sessionmaker(bind=engine)

def create_tables():
    Base.metadata.create_all(engine)

def drop_tables():
    Base.metadata.drop_all(engine)

@contextmanager
def session_scope():
    session = Session()
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()

def db_User_exists(email):
    with session_scope() as session:
        return session.query(User).filter(User.email == email).count() > 0

def db_Invitee_exists(email):
    with session_scope() as session:
        return session.query(Invitee).filter(Invitee.email == email).count() > 0

def db_Invitee_get(email):
    with session_scope() as session:
        result = session.query(Invitee).filter(Invitee.email == email).first()
        return result

def db_User_add(user):
    with session_scope() as session:
        session.add(user)

def db_Invitee_add(invitee):
    with session_scope() as session:
        session.add(invitee)
