from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, auto_field

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column('id', Integer, primary_key=True) 
    fullname = Column(String(256), nullable=False)
    email = Column(String(320), nullable=False, unique=True, index=True)
    email_verified = Column(Boolean, default = False, server_default="FALSE")
    verify_code = Column(String(32))
    invitee_id = Column(Integer, ForeignKey('invitees.id'), nullable=False, unique=True)
    registered_usr = relationship("Invitee", back_populates="registered_usr")    
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
    registered_usr = relationship("User", back_populates="invite", uselist=False)

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
    state_issued_at = Column(DateTime)
    credentials = Column(JSONB)

class GMailAuthSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = GMailAuth
        load_instance = True

class SpotifyAuth(Base):
    __tablename__ = 'spotifyauths'
    id = Column('id', Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, unique=True)
    user = relationship("User", back_populates="spotify_auth")
    state = Column(String(32), unique = True, index = True)
    state_issued_at = Column(DateTime)
    token_info = Column(JSONB)

User.spotify_auth = relationship("SpotifyAuth", uselist=False, back_populates="user")
