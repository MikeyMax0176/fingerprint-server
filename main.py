"""
Fingerprint Server — FastAPI backend
-------------------------------------
Routes:
  GET  /              → Landing page (what NFC tag opens)
  POST /api/fingerprint → Receive fingerprint from browser JS, store in DB
  GET  /dashboard     → Admin view of all logged visitors
  GET  /visitor/{id}  → Detail page for one visitor
"""
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import create_tables, get_db, Visitor

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = FastAPI(title="Fingerprint Server")
templates = Jinja2Templates(directory="templates")
create_tables()

# ---------------------------------------------------------------------------
# Customise these — shown on the landing page
# ---------------------------------------------------------------------------
WELCOME_MESSAGE = "Welcome! Your device has been registered."
DEMO_SUBTITLE   = "NFC Fingerprint Demo"


# ---------------------------------------------------------------------------
# Pydantic schema — all fields from the browser
# ---------------------------------------------------------------------------
class FingerprintPayload(BaseModel):
    # Core
    user_agent:           str   = ""
    platform:             str   = ""
    screen_width:         int   = 0
    screen_height:        int   = 0
    language:             str   = ""
    timezone:             str   = ""
    touch_points:         int   = 0
    hardware_concurrency: int   = 0
    device_memory:        str   = "unknown"
    canvas_hash:          str   = ""
    color_depth:          int   = 0
    # Screen extras
    avail_width:          int   = 0
    avail_height:         int   = 0
    pixel_depth:          int   = 0
    pixel_ratio:          float = 1.0
    orientation:          str   = ""
    # WebGL
    webgl_renderer:       str   = ""
    webgl_vendor:         str   = ""
    webgl_version:        str   = ""
    webgl_shading:        str   = ""
    webgl_extensions:     int   = 0
    webgl_max_texture:    int   = 0
    webgl_max_viewport:   str   = ""
    # Audio
    audio_hash:           str   = ""
    # Fonts
    fonts:                List[str] = []
    fonts_count:          int   = 0
    # Math
    math_hash:            str   = ""
    # Speech
    speech_voices:        int   = 0
    # Connection
    connection_type:      str   = "unknown"
    effective_type:       str   = "unknown"
    downlink:             float = 0.0
    rtt:                  int   = 0
    save_data:            bool  = False
    # Media devices
    cameras:              int   = 0
    microphones:          int   = 0
    speakers:             int   = 0
    # Permissions, storage, css, nav, battery stored as raw JSON only
    permissions:          Optional[Dict[str, Any]] = None
    storage:              Optional[Dict[str, Any]] = None
    css_features:         Optional[Dict[str, Any]] = None
    nav:                  Optional[Dict[str, Any]] = None
    battery:              Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make_visitor_id(p: FingerprintPayload) -> str:
    """SHA-256 over the highest-entropy attributes → 16-char hex ID."""
    parts = [
        p.user_agent,
        p.platform,
        str(p.screen_width), str(p.screen_height),
        str(p.pixel_ratio),
        p.timezone,
        str(p.hardware_concurrency),
        p.device_memory,
        p.canvas_hash,
        p.audio_hash,
        p.webgl_renderer,
        p.webgl_vendor,
        p.math_hash,
        ",".join(sorted(p.fonts)),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def make_device_label(p: FingerprintPayload) -> str:
    ua = p.user_agent.lower()
    if "iphone" in ua:   os_part = "iPhone"
    elif "ipad" in ua:   os_part = "iPad"
    elif "android" in ua: os_part = "Android"
    elif "mac" in ua:    os_part = "Mac"
    elif "windows" in ua: os_part = "Windows"
    elif "linux" in ua:  os_part = "Linux"
    else:                os_part = p.platform or "Unknown"

    if "edg/" in ua:     browser = "Edge"
    elif "chrome" in ua and "safari" in ua: browser = "Chrome"
    elif "firefox" in ua: browser = "Firefox"
    elif "safari" in ua: browser = "Safari"
    else:                browser = "Browser"

    return f"{os_part} / {browser}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "welcome_message": WELCOME_MESSAGE,
        "demo_subtitle": DEMO_SUBTITLE,
    })


@app.post("/api/fingerprint")
async def receive_fingerprint(payload: FingerprintPayload, db: Session = Depends(get_db)):
    visitor_id = make_visitor_id(payload)
    existing   = db.query(Visitor).filter(Visitor.visitor_id == visitor_id).first()

    if existing:
        existing.last_seen   = datetime.utcnow()
        existing.visit_count += 1
        db.commit()
        return {
            "visitor_id":   visitor_id,
            "status":       "returning",
            "device_label": existing.device_label,
            "visit_count":  existing.visit_count,
        }

    device_label = make_device_label(payload)
    bat          = payload.battery or {}

    new_visitor = Visitor(
        visitor_id          = visitor_id,
        device_label        = device_label,
        user_agent          = payload.user_agent,
        platform            = payload.platform,
        language            = payload.language,
        timezone            = payload.timezone,
        hardware_concurrency= payload.hardware_concurrency,
        device_memory       = payload.device_memory,
        touch_points        = payload.touch_points,
        plugins_count       = (payload.nav or {}).get("plugins_count", 0),
        do_not_track        = (payload.nav or {}).get("do_not_track", "unset"),
        webdriver           = bool((payload.nav or {}).get("webdriver", False)),
        pdf_viewer          = bool((payload.nav or {}).get("pdf_viewer", False)),
        screen_resolution   = f"{payload.screen_width}x{payload.screen_height}",
        avail_resolution    = f"{payload.avail_width}x{payload.avail_height}",
        color_depth         = payload.color_depth,
        pixel_depth         = payload.pixel_depth,
        pixel_ratio         = payload.pixel_ratio,
        orientation         = payload.orientation,
        canvas_hash         = payload.canvas_hash,
        webgl_renderer      = payload.webgl_renderer,
        webgl_vendor        = payload.webgl_vendor,
        webgl_version       = payload.webgl_version,
        webgl_shading       = payload.webgl_shading,
        webgl_extensions    = payload.webgl_extensions,
        webgl_max_texture   = payload.webgl_max_texture,
        webgl_max_viewport  = payload.webgl_max_viewport,
        audio_hash          = payload.audio_hash,
        fonts_detected      = json.dumps(payload.fonts),
        fonts_count         = payload.fonts_count,
        math_hash           = payload.math_hash,
        speech_voices       = payload.speech_voices,
        connection_type     = payload.connection_type,
        effective_type      = payload.effective_type,
        downlink            = payload.downlink,
        rtt                 = payload.rtt,
        cameras             = payload.cameras,
        microphones         = payload.microphones,
        speakers            = payload.speakers,
        battery_charging    = str(bat.get("charging", "")) if bat.get("charging") is not None else "unknown",
        battery_level       = str(bat.get("level", ""))    if bat.get("level")    is not None else "unknown",
        raw_data            = json.dumps(payload.dict()),
    )
    db.add(new_visitor)
    db.commit()
    return {
        "visitor_id":   visitor_id,
        "status":       "new",
        "device_label": device_label,
        "visit_count":  1,
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    visitors = db.query(Visitor).order_by(Visitor.last_seen.desc()).all()
    return templates.TemplateResponse("dashboard.html", {
        "request":  request,
        "visitors": visitors,
        "total":    len(visitors),
    })


@app.get("/visitor/{visitor_id}", response_class=HTMLResponse)
async def visitor_detail(visitor_id: str, request: Request, db: Session = Depends(get_db)):
    visitor = db.query(Visitor).filter(Visitor.visitor_id == visitor_id).first()
    if not visitor:
        return HTMLResponse("<h2>Visitor not found</h2>", status_code=404)
    raw   = json.loads(visitor.raw_data)   if visitor.raw_data    else {}
    fonts = json.loads(visitor.fonts_detected) if visitor.fonts_detected else []
    return templates.TemplateResponse("visitor.html", {
        "request": request,
        "visitor": visitor,
        "raw":     raw,
        "fonts":   fonts,
    })
