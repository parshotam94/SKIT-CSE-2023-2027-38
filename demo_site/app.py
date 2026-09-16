from typing import Dict, Any
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import uvicorn

app = FastAPI(
    title="WAF Demo",
    description="Interactive Web Application Firewall testing site",
    version="1.0.0"
)

# Allow frontend requests during local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
HTML_FILE = BASE_DIR / "index.html"


# -----------------------------
# Frontend
# -----------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(
        content=HTML_FILE.read_text(encoding="utf-8")
    )


# -----------------------------
# Health
# -----------------------------

@app.get("/health")
async def health() -> Dict[str, str]:
    return {
        "status": "ok",
        "service": "WAF Demo Application"
    }


# -----------------------------
# Normal API endpoints
# -----------------------------

@app.get("/api/events")
async def events() -> Dict[str, Any]:
    return {
        "status": "success",
        "events": [
            {
                "id": 1,
                "title": "AI & ML Workshop",
                "date": "2026-09-20",
                "location": "Innovation Lab"
            },
            {
                "id": 2,
                "title": "Cyber Security Seminar",
                "date": "2026-09-25",
                "location": "Auditorium"
            },
            {
                "id": 3,
                "title": "Cloud Computing Meetup",
                "date": "2026-09-28",
                "location": "Tech Hub"
            }
        ]
    }


@app.get("/api/profile")
async def profile() -> Dict[str, Any]:
    return {
        "status": "success",
        "name": "Student",
        "role": "member",
        "department": "Computer Science",
        "access": "standard"
    }


@app.get("/api/search")
async def search(q: str = "") -> Dict[str, Any]:
    return {
        "status": "success",
        "query": q,
        "results": [
            {
                "id": 1,
                "title": "Machine Learning",
                "category": "Technology"
            },
            {
                "id": 2,
                "title": "Cyber Security",
                "category": "Security"
            }
        ]
    }


@app.get("/api/files")
async def files(path: str = "") -> Dict[str, Any]:
    return {
        "status": "not_found",
        "requested_path": path
    }


# -----------------------------
# Authentication
# -----------------------------

@app.post("/api/auth/login")
async def login(request: Request) -> JSONResponse:

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON"
        )

    username = data.get("username", "")
    password = data.get("password", "")

    if username == "user" and password == "password":
        return JSONResponse({
            "status": "ok",
            "message": "Authentication successful",
            "token": "demo-token"
        })

    raise HTTPException(
        status_code=401,
        detail="Invalid credentials"
    )


# -----------------------------
# Command Injection Test
# -----------------------------

@app.post("/api/exec")
async def exec_cmd(request: Request) -> Dict[str, Any]:

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON"
        )

    command = data.get("cmd", "")

    # IMPORTANT:
    # This endpoint does NOT execute the command.
    # It only echoes it for WAF testing.
    return {
        "status": "queued",
        "command": command,
        "execution": "disabled"
    }


# -----------------------------
# Custom API tester
# -----------------------------

@app.post("/api/test")
async def custom_test(request: Request):

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON"
        )

    return {
        "status": "received",
        "method": data.get("method", "GET"),
        "payload": data.get("payload", "")
    }


# -----------------------------
# Run application
# -----------------------------

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=5000,
        reload=True
    )