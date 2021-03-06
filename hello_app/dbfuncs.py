from .dbclasses import Base, User, Invitee, GMailAuth, SpotifyAuth
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import JSON

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

def db_Invitee_idFor(email):
    with session_scope() as session:
        result = session.query(Invitee).filter(Invitee.email == email).first()
        if not result is None:
            result = int(result.id)
        return result
# when returning object on a closed session, could try session.expire_on_commit = False
# and probably session.expunge(object)

def db_User_add(user):
    with session_scope() as session:
        session.add(user)

def db_Invitee_add(invitee):
    with session_scope() as session:
        session.add(invitee)
        session.flush()
        if not invitee.id:
            raise Exception("Could not get new invitee id")
        return invitee.id

def db_put_gmail_send_auth(jsonData):
    with session_scope() as session:
        result = session.query(GMailAuth).filter(GMailAuth.email == jsonData.get('email')).first()
        if result is None:
            result = GMailAuth()
            session.add(result)
        result.email = jsonData.get('email')
        result.fullname = jsonData.get('fullname')
        result.client_secrets = jsonData.get('client_secrets')
        result.redirect_uri = jsonData.get('redirect_uri')
        result.scopes = jsonData.get('scopes')
        result.state = None
        result.state_issued_at = None
        result.credentials = None

def db_get_AllInvitees(session):
    return session.query(Invitee).all()

def db_get_Invitee_by_Id(id, session):
    return session.query(Invitee).filter(Invitee.id == id).first()

def db_get_GMailAuth(email, session):
    return session.query(GMailAuth).filter(GMailAuth.email == email).first()

def db_get_GMailAuth_by_state(state, session):
    return session.query(GMailAuth).filter(GMailAuth.state == state).first()

def db_get_SpotifyAuth_by_state(state, session):
    return session.query(SpotifyAuth).filter(SpotifyAuth.state == state).first()

def db_get_User_by_email(email, session):
    return session.query(User).filter(User.email == email).first()

def db_get_Users_with_spotify_token(session):
    return session.query(User).join(SpotifyAuth).filter(User.spotify_auth != None, SpotifyAuth.token_info != JSON.NULL)

def db_is_User_email_verified(email):
    result = False
    with session_scope() as session:
        user = db_get_User_by_email(email, session)
        if user and user.email_verified:
            result = True
        
    return result