"""SOC Sentinel — FastAPI server entry point.

Run with:
    uvicorn server.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
import os
import sys

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure project root is on the path for graph/ imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

load_dotenv()

# ---------------------------------------------------------------------------
# Structured logging configuration
# ---------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SOC Sentinel API",
    description="Security Operations Center AI Agent — Backend API",
    version="1.0.0",
)

# CORS — allow the Next.js dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
from server.routes_alerts import router as alerts_router
from server.routes_chat import router as chat_router
from server.routes_pipeline import router as pipeline_router
from server.ws_alerts import router as ws_alerts_router
from server.ws_pipeline import router as ws_pipeline_router

app.include_router(alerts_router)
app.include_router(chat_router)
app.include_router(pipeline_router)
app.include_router(ws_alerts_router)
app.include_router(ws_pipeline_router)

logger.info("SOC Sentinel API starting up (log_level=%s)", LOG_LEVEL)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "soc-sentinel"}
