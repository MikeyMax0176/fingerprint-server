"""
Database setup using SQLAlchemy.
- On Railway: uses PostgreSQL (DATABASE_URL env var set automatically)
- Locally:    falls back to SQLite (fingerprints.db)
"""
import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./fingerprints.db")

# Railway gives a postgres:// URL; SQLAlchemy needs postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Visitor(Base):
    """One row per unique device fingerprint."""
    __tablename__ = "visitors"

    id               = Column(Integer, primary_key=True, index=True)
    visitor_id       = Column(String, unique=True, index=True)

    # Network (server-side)
    ip_address       = Column(String)
    user_country     = Column(String)    # from CF-IPCountry header if available

    # Identity / label
    device_label     = Column(String)

    # Core navigator
    user_agent       = Column(Text)
    platform         = Column(String)
    language         = Column(String)
    languages        = Column(String)    # full list e.g. "en-US, en, fr"
    timezone         = Column(String)
    timezone_offset  = Column(Integer)   # minutes from UTC
    hardware_concurrency = Column(Integer)
    device_memory    = Column(String)
    touch_points     = Column(Integer)
    plugins_count    = Column(Integer)
    do_not_track     = Column(String)
    webdriver        = Column(Boolean)
    pdf_viewer       = Column(Boolean)
    vendor           = Column(String)    # e.g. "Apple Computer, Inc."

    # Screen
    screen_resolution  = Column(String)
    avail_resolution   = Column(String)
    color_depth        = Column(Integer)
    pixel_depth        = Column(Integer)
    pixel_ratio        = Column(Float)
    orientation        = Column(String)

    # Input / pointer
    pointer_type     = Column(String)    # fine / coarse / none
    hover_support    = Column(String)    # hover / none
    any_pointer      = Column(String)
    any_hover        = Column(String)

    # CSS media features
    prefers_dark     = Column(String)    # dark / light
    prefers_reduced  = Column(String)    # reduce / no-preference
    color_gamut      = Column(String)    # srgb / p3 / rec2020
    hdr              = Column(String)    # high / standard / no-preference
    forced_colors    = Column(String)    # active / none

    # Canvas
    canvas_hash      = Column(String)

    # WebGL
    webgl_renderer      = Column(String)
    webgl_vendor        = Column(String)
    webgl_version       = Column(String)
    webgl_shading       = Column(String)
    webgl_extensions    = Column(Integer)
    webgl_max_texture   = Column(Integer)
    webgl_max_viewport  = Column(String)

    # Audio
    audio_hash       = Column(String)

    # Fonts
    fonts_detected   = Column(Text)      # JSON list
    fonts_count      = Column(Integer)

    # Math entropy
    math_hash        = Column(Text)

    # Speech
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

    # Codecs
    video_codecs     = Column(String)    # JSON
    audio_codecs     = Column(String)    # JSON

    # Battery
    battery_charging = Column(String)
    battery_level    = Column(String)

    # WebRTC local IP
    local_ip         = Column(String)

    # Full raw JSON
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
