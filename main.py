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

# Create DB tables on startup
create_tables()

# ---------------------------------------------------------------------------
# Customise these strings — they appear on the landing page after a tap
# ---------------------------------------------------------------------------
WELCOME_MESSAGE = "Welcome! Your device has been registered."
DEMO_SUBTITLE   = "NFC Fingerprint Demo"


# ---------------------------------------------------------------------------
# Pydantic schema for the data sent by the browser
# ---------------------------------------------------------------------------
class FingerprintPayload(BaseModel):
    user_agent: str = ""
    platform: str = ""
    screen_width: int = 0
    screen_height: int = 0
    language: str = ""
    timezone: str = ""
    touch_points: int = 0
    hardware_concurrency: int = 0
    device_memory: str = "unknown"
    canvas_hash: str = ""
    color_depth: int = 0


# ---------------------------------------------------------------------------
# Helper — build a stable SHA-256 ID from fingerprint attributes
# ---------------------------------------------------------------------------
def make_visitor_id(payload: FingerprintPayload) -> str:
    raw = "|".join([
        payload.user_agent,
        payload.platform,
        str(payload.screen_width),
        str(payload.screen_height),
        payload.timezone,
        str(payload.hardware_concurrency),
        payload.canvas_hash,
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def make_device_label(payload: FingerprintPayload) -> str:
    ua = payload.user_agent.lower()
    # Detect OS
    if "iphone" in ua:
        os_part = "iPhone"
    elif "ipad" in ua:
        os_part = "iPad"
    elif "android" in ua:
        os_part = "Android"
    elif "mac" in ua:
        os_part = "Mac"
    elif "windows" in ua:
        os_part = "Windows"
    elif "linux" in ua:
        os_part = "Linux"
    else:
        os_part = payload.platform or "Unknown OS"

    # Detect browser
    if "edg/" in ua:
        browser = "Edge"
    elif "chrome" in ua and "safari" in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua:
        browser = "Safari"
    else:
        browser = "Browser"

    return f"{os_part} / {browser}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    """Landing page — opened when user taps NFC tag."""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "welcome_message": WELCOME_MESSAGE,
        "demo_subtitle": DEMO_SUBTITLE,
    })


@app.post("/api/fingerprint")
async def receive_fingerprint(payload: FingerprintPayload, db: Session = Depends(get_db)):
    """
    Called by the browser JS after collecting fingerprint attributes.
    Returns whether this is a new or returning visitor.
    """
    visitor_id = make_visitor_id(payload)
    existing = db.query(Visitor).filter(Visitor.visitor_id == visitor_id).first()

    if existing:
        existing.last_seen = datetime.utcnow()
        existing.visit_count += 1
        db.commit()
        return {
            "visitor_id": visitor_id,
            "status": "returning",
            "device_label": existing.device_label,
            "visit_count": existing.visit_count,
        }
    else:
        device_label = make_device_label(payload)
        new_visitor = Visitor(
            visitor_id=visitor_id,
            device_label=device_label,
            user_agent=payload.user_agent,
            platform=payload.platform,
            screen_resolution=f"{payload.screen_width}x{payload.screen_height}",
            language=payload.language,
            timezone=payload.timezone,
            touch_points=payload.touch_points,
            hardware_concurrency=payload.hardware_concurrency,
            device_memory=payload.device_memory,
            canvas_hash=payload.canvas_hash,
            raw_data=json.dumps(payload.dict()),
        )
        db.add(new_visitor)
        db.commit()
        return {
            "visitor_id": visitor_id,
            "status": "new",
            "device_label": device_label,
            "visit_count": 1,
        }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Admin dashboard — lists all logged visitors."""
    visitors = db.query(Visitor).order_by(Visitor.last_seen.desc()).all()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "visitors": visitors,
        "total": len(visitors),
    })


@app.get("/visitor/{visitor_id}", response_class=HTMLResponse)
async def visitor_detail(visitor_id: str, request: Request, db: Session = Depends(get_db)):
    """Detail view for a single visitor."""
    visitor = db.query(Visitor).filter(Visitor.visitor_id == visitor_id).first()
    if not visitor:
        return HTMLResponse("<h2>Visitor not found</h2>", status_code=404)
    raw = json.loads(visitor.raw_data) if visitor.raw_data else {}
    return templates.TemplateResponse("visitor.html", {
        "request": request,
        "visitor": visitor,
        "raw": raw,
    })
