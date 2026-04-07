"""
SQLite database setup using SQLAlchemy.
All visitor fingerprints are stored in fingerprints.db in this directory.
"""
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./fingerprints.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Visitor(Base):
    """One row per unique device fingerprint."""
    __tablename__ = "visitors"

    id = Column(Integer, primary_key=True, index=True)
    visitor_id = Column(String, unique=True, index=True)   # SHA-256 hash of attributes
    device_label = Column(String)                           # Human-readable label, e.g. "iPhone / Safari"
    user_agent = Column(Text)
    platform = Column(String)
    screen_resolution = Column(String)
    language = Column(String)
    timezone = Column(String)
    touch_points = Column(Integer)
    hardware_concurrency = Column(Integer)
    device_memory = Column(String)
    canvas_hash = Column(String)
    raw_data = Column(Text)                                 # Full JSON from browser
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    visit_count = Column(Integer, default=1)


def create_tables():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
