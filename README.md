# Fingerprint Server

A demo server that logs unique device fingerprints when a user taps an **NFC tag**.

## How it works

1. An NFC tag is programmed with the URL of this server (e.g. `https://your-server.com/`)
2. A user taps the tag with their phone or device
3. The browser opens the landing page and silently collects device attributes
4. The server stores a unique fingerprint in the database
5. New visitors see a "Welcome!" message; returning visitors see their visit count
6. You can view all logged devices at `/dashboard`

## Pages

| URL | What it does |
|-----|-------------|
| `/` | Landing page (what the NFC tag points to) |
| `/dashboard` | Admin view of all unique visitors |
| `/visitor/<id>` | Detail view for one visitor |

## Customise the welcome message

Open `main.py` and change these two lines near the top:

```python
WELCOME_MESSAGE = "Welcome! Your device has been registered."
DEMO_SUBTITLE   = "NFC Fingerprint Demo"
```

## Running locally

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Then open `http://localhost:8000` in your browser.  
The dashboard is at `http://localhost:8000/dashboard`.

## Deploying (so NFC tags can reach it)

You need a public URL for your NFC tags to work from any device.  
Easiest options:

- **Railway** — free tier, one-click deploy from GitHub
- **Render** — free tier, connect your GitHub repo
- **Fly.io** — free tier, deploy with `flyctl deploy`

All three will give you a public `https://` URL that you program into your NFC tags.

## Project structure

```
fingerprint_server/
├── main.py          ← FastAPI routes + business logic
├── database.py      ← SQLite database setup
├── requirements.txt ← Python dependencies
└── templates/
    ├── index.html   ← Landing page (opened by NFC tap)
    ├── dashboard.html ← Admin view
    └── visitor.html ← Single-visitor detail
```
