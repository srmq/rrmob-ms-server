from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import JSONB

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column('id', Integer, primary_key=True) 
    fullname = Column(String(256), nullable=False)
    email = Column(String(320), nullable=False, unique=True, index=True)
    email_verified = Column(Boolean, default = False, server_default="FALSE")
    invitee_id = Column(Integer, ForeignKey('invitees.id'), nullable=False)
    pass_hash = Column(String(128), nullable=False)
    pass_salt = Column(String(32), nullable=False)
    spot_id = Column(String(1024))
    auth_info = Column(JSONB)
    user_info = Column(JSONB)

    def __repr__(self):
        return "{\"id\": %s, \"fullname\": \"%s\", \"email\": \"%s\", \"email_verified\": \"%s\", \"invitee_id\": \"%s\", \"pass_hash\": \"%s\", \"pass_salt\": \"%s\", \"spot_id\": \"%s\", \"auth_info\": \"%s\", \"user_info\": \"%s\"}" % (self.id, self.fullname, self.email, self.email_verified, self.invitee_id, self.pass_hash, self.pass_salt, self.spot_id, self.auth_info, self.user_info)

class Invitee(Base):
    __tablename__ = 'invitees'
    id = Column('id', Integer, primary_key=True)
    email = Column(String(320), nullable=False, unique=True, index=True)

    def __repr__(self):
        return "{\"id\": %s, \"email\" = %s}" % (self.id, self.email)

class GMailAuth(Base):
    __tablename__ = 'gmailauth'
    id = Column('id', Integer, primary_key=True)
    email = Column(String(320), nullable=False, unique=True, index=True)
    fullname = Column(String(256), nullable=False)
    client_secrets = Column(JSONB)
    redirect_uri = Column(String(1024))
    scopes = Column(JSONB)
    state = Column(Text, unique = True, index=True)
    stateIssuedAt = Column(DateTime)
    credentials = Column(JSONB)
