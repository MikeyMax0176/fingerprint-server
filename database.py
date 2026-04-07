"""
SQLite database setup using SQLAlchemy.
All visitor fingerprints are stored in fingerprints.db in this directory.
"""
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, Boolean
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

    id               = Column(Integer, primary_key=True, index=True)
    visitor_id       = Column(String, unique=True, index=True)   # SHA-256 of key attributes

    # Identity / label
    device_label     = Column(String)      # e.g. "iPhone / Safari"

    # Core navigator
    user_agent       = Column(Text)
    platform         = Column(String)
    language         = Column(String)
    timezone         = Column(String)
    hardware_concurrency = Column(Integer)
    device_memory    = Column(String)
    touch_points     = Column(Integer)
    plugins_count    = Column(Integer)
    do_not_track     = Column(String)
    webdriver        = Column(Boolean)
    pdf_viewer       = Column(Boolean)

    # Screen
    screen_resolution = Column(String)     # e.g. "1920x1080"
    avail_resolution  = Column(String)     # available (excluding taskbar)
    color_depth       = Column(Integer)
    pixel_depth       = Column(Integer)
    pixel_ratio       = Column(Float)
    orientation       = Column(String)

    # Canvas
    canvas_hash      = Column(String)

    # WebGL — very high entropy
    webgl_renderer   = Column(String)
    webgl_vendor     = Column(String)
    webgl_version    = Column(String)
    webgl_shading    = Column(String)
    webgl_extensions = Column(Integer)
    webgl_max_texture = Column(Integer)
    webgl_max_viewport = Column(String)

    # Audio fingerprint
    audio_hash       = Column(String)

    # Fonts
    fonts_detected   = Column(Text)        # JSON list of detected font names
    fonts_count      = Column(Integer)

    # Math entropy
    math_hash        = Column(Text)

    # Speech synthesis
    speech_voices    = Column(Integer)

    # Connection
    connection_type  = Column(String)
    effective_type   = Column(String)
    downlink         = Column(Float)
    rtt              = Column(Integer)

    # Media devices
    cameras          = Column(Integer)
    microphones      = Column(Integer)
    speakers         = Column(Integer)

    # Battery
    battery_charging = Column(String)
    battery_level    = Column(String)

    # Full raw JSON payload from browser
    raw_data         = Column(Text)

    # Visit tracking
    first_seen       = Column(DateTime, default=datetime.utcnow)
    last_seen        = Column(DateTime, default=datetime.utcnow)
    visit_count      = Column(Integer, default=1)


def create_tables():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
