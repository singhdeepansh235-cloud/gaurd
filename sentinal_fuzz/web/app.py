"""FastAPI application factory for Sentinal-Fuzz Web Interface."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager

from sentinal_fuzz.web.services.db import get_db, close_db

WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
TEMPLATE_DIR = WEB_DIR / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await get_db()
    yield
    # Shutdown
    await close_db()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Sentinal-Fuzz",
        description="Intelligent DAST Scanner — Web Interface",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Mount static files
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    (STATIC_DIR / "css").mkdir(exist_ok=True)
    (STATIC_DIR / "js").mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Setup templates
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    app.state.templates = templates

    # Register routes
    from sentinal_fuzz.web.routes.pages import router as pages_router
    from sentinal_fuzz.web.routes.api import router as api_router
    from sentinal_fuzz.web.routes.ws import router as ws_router

    app.include_router(pages_router)
    app.include_router(api_router, prefix="/api")
    app.include_router(ws_router)

    return app
