"""
Fingerprint Server — FastAPI backend
"""
import hashlib
import json
import os
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Depends, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import create_tables, get_db, Visitor

app = FastAPI(title="Fingerprint Server")
templates = Jinja2Templates(directory="templates")
security = HTTPBasic()
create_tables()

# ---------------------------------------------------------------------------
# Dashboard auth — set DASHBOARD_USER and DASHBOARD_PASS in Railway settings
# Defaults to admin / changeme if not set (change these in Railway!)
# ---------------------------------------------------------------------------
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "changeme")


def require_auth(credentials: HTTPBasicCredentials = Depends(security)):
    """Protect any route with HTTP Basic Auth."""
    user_ok = secrets.compare_digest(credentials.username.encode(), DASHBOARD_USER.encode())
    pass_ok = secrets.compare_digest(credentials.password.encode(), DASHBOARD_PASS.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

WELCOME_MESSAGE = "Welcome! Your device has been registered."
DEMO_SUBTITLE   = "NFC Fingerprint Demo"


# ---------------------------------------------------------------------------
# Pydantic schema
# ---------------------------------------------------------------------------
class FingerprintPayload(BaseModel):
    # Core
    user_agent:           str   = ""
    platform:             str   = ""
    screen_width:         int   = 0
    screen_height:        int   = 0
    language:             str   = ""
    languages:            str   = ""
    timezone:             str   = ""
    timezone_offset:      int   = 0
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
    # Input / pointer
    pointer_type:         str   = ""
    hover_support:        str   = ""
    any_pointer:          str   = ""
    any_hover:            str   = ""
    # CSS media features
    prefers_dark:         str   = ""
    prefers_reduced:      str   = ""
    color_gamut:          str   = ""
    hdr:                  str   = ""
    forced_colors:        str   = ""
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
    # Codecs
    video_codecs:         Optional[Dict[str, Any]] = None
    audio_codecs:         Optional[Dict[str, Any]] = None
    # WebRTC local IP
    local_ip:             str   = ""
    # Dicts stored as JSON
    permissions:          Optional[Dict[str, Any]] = None
    storage:              Optional[Dict[str, Any]] = None
    css_features:         Optional[Dict[str, Any]] = None
    nav:                  Optional[Dict[str, Any]] = None
    battery:              Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    # Railway (and most proxies) set X-Forwarded-For
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def make_visitor_id(p: FingerprintPayload) -> str:
    parts = [
        p.user_agent, p.platform,
        str(p.screen_width), str(p.screen_height), str(p.pixel_ratio),
        p.timezone, str(p.hardware_concurrency), p.device_memory,
        p.canvas_hash, p.audio_hash,
        p.webgl_renderer, p.webgl_vendor,
        p.math_hash, ",".join(sorted(p.fonts)),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def make_device_label(p: FingerprintPayload) -> str:
    ua = p.user_agent.lower()
    if "iphone" in ua:    os_part = "iPhone"
    elif "ipad" in ua:    os_part = "iPad"
    elif "android" in ua: os_part = "Android"
    elif "mac" in ua:     os_part = "Mac"
    elif "windows" in ua: os_part = "Windows"
    elif "linux" in ua:   os_part = "Linux"
    else:                 os_part = p.platform or "Unknown"

    if "edg/" in ua:                          browser = "Edge"
    elif "chrome" in ua and "safari" in ua:   browser = "Chrome"
    elif "firefox" in ua:                     browser = "Firefox"
    elif "safari" in ua:                      browser = "Safari"
    else:                                     browser = "Browser"

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
async def receive_fingerprint(
    payload: FingerprintPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    visitor_id  = make_visitor_id(payload)
    ip_address  = get_client_ip(request)
    country     = request.headers.get("cf-ipcountry", "")   # Cloudflare header
    existing    = db.query(Visitor).filter(Visitor.visitor_id == visitor_id).first()

    if existing:
        existing.last_seen   = datetime.utcnow()
        existing.visit_count += 1
        existing.ip_address  = ip_address   # update to latest IP
        db.commit()
        return {
            "visitor_id":   visitor_id,
            "status":       "returning",
            "device_label": existing.device_label,
            "visit_count":  existing.visit_count,
        }

    device_label = make_device_label(payload)
    bat          = payload.battery or {}
    nav          = payload.nav or {}

    new_visitor = Visitor(
        visitor_id           = visitor_id,
        ip_address           = ip_address,
        user_country         = country,
        device_label         = device_label,
        user_agent           = payload.user_agent,
        platform             = payload.platform,
        language             = payload.language,
        languages            = payload.languages,
        timezone             = payload.timezone,
        timezone_offset      = payload.timezone_offset,
        hardware_concurrency = payload.hardware_concurrency,
        device_memory        = payload.device_memory,
        touch_points         = payload.touch_points,
        plugins_count        = nav.get("plugins_count", 0),
        do_not_track         = nav.get("do_not_track", "unset"),
        webdriver            = bool(nav.get("webdriver", False)),
        pdf_viewer           = bool(nav.get("pdf_viewer", False)),
        vendor               = nav.get("vendor", ""),
        screen_resolution    = f"{payload.screen_width}x{payload.screen_height}",
        avail_resolution     = f"{payload.avail_width}x{payload.avail_height}",
        color_depth          = payload.color_depth,
        pixel_depth          = payload.pixel_depth,
        pixel_ratio          = payload.pixel_ratio,
        orientation          = payload.orientation,
        pointer_type         = payload.pointer_type,
        hover_support        = payload.hover_support,
        any_pointer          = payload.any_pointer,
        any_hover            = payload.any_hover,
        prefers_dark         = payload.prefers_dark,
        prefers_reduced      = payload.prefers_reduced,
        color_gamut          = payload.color_gamut,
        hdr                  = payload.hdr,
        forced_colors        = payload.forced_colors,
        canvas_hash          = payload.canvas_hash,
        webgl_renderer       = payload.webgl_renderer,
        webgl_vendor         = payload.webgl_vendor,
        webgl_version        = payload.webgl_version,
        webgl_shading        = payload.webgl_shading,
        webgl_extensions     = payload.webgl_extensions,
        webgl_max_texture    = payload.webgl_max_texture,
        webgl_max_viewport   = payload.webgl_max_viewport,
        audio_hash           = payload.audio_hash,
        fonts_detected       = json.dumps(payload.fonts),
        fonts_count          = payload.fonts_count,
        math_hash            = payload.math_hash,
        speech_voices        = payload.speech_voices,
        connection_type      = payload.connection_type,
        effective_type       = payload.effective_type,
        downlink             = payload.downlink,
        rtt                  = payload.rtt,
        cameras              = payload.cameras,
        microphones          = payload.microphones,
        speakers             = payload.speakers,
        video_codecs         = json.dumps(payload.video_codecs or {}),
        audio_codecs         = json.dumps(payload.audio_codecs or {}),
        battery_charging     = str(bat.get("charging", "")) if bat.get("charging") is not None else "unknown",
        battery_level        = str(bat.get("level", ""))    if bat.get("level")    is not None else "unknown",
        local_ip             = payload.local_ip,
        raw_data             = json.dumps(payload.dict()),
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
async def dashboard(request: Request, db: Session = Depends(get_db), _=Depends(require_auth)):
    visitors = db.query(Visitor).order_by(Visitor.last_seen.desc()).all()
    return templates.TemplateResponse("dashboard.html", {
        "request":  request,
        "visitors": visitors,
        "total":    len(visitors),
    })


@app.get("/visitor/{visitor_id}", response_class=HTMLResponse)
async def visitor_detail(visitor_id: str, request: Request, db: Session = Depends(get_db), _=Depends(require_auth)):
    visitor = db.query(Visitor).filter(Visitor.visitor_id == visitor_id).first()
    if not visitor:
        return HTMLResponse("<h2>Visitor not found</h2>", status_code=404)
    raw   = json.loads(visitor.raw_data)       if visitor.raw_data       else {}
    fonts = json.loads(visitor.fonts_detected) if visitor.fonts_detected else []
    vcod  = json.loads(visitor.video_codecs)   if visitor.video_codecs   else {}
    acod  = json.loads(visitor.audio_codecs)   if visitor.audio_codecs   else {}
    return templates.TemplateResponse("visitor.html", {
        "request":      request,
        "visitor":      visitor,
        "raw":          raw,
        "fonts":        fonts,
        "video_codecs": vcod,
        "audio_codecs": acod,
    })
