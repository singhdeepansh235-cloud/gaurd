"""FastAPI application factory for Sentinal-Fuzz Web Interface."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sentinal_fuzz.web.services.db import close_db, get_db

WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
TEMPLATE_DIR = WEB_DIR / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
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

    # Enable CORS for the Chrome Extension
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
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
    from sentinal_fuzz.web.routes.api import router as api_router
    from sentinal_fuzz.web.routes.pages import router as pages_router
    from sentinal_fuzz.web.routes.ws import router as ws_router

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon_ico() -> Response:
        return Response(
            content=(
                "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
                "<rect width='100' height='100' rx='20' fill='#4d9eff'/>"
                "<path d='M50 15 L80 30 V55 C80 72 50 88 50 88 C50 88 20 72 20 55 V30 Z' "
                "fill='none' stroke='white' stroke-width='6'/>"
                "</svg>"
            ),
            media_type="image/svg+xml",
        )

    @app.get("/favicon.png", include_in_schema=False)
    async def favicon_png() -> Response:
        return await favicon_ico()

    app.include_router(pages_router)
    app.include_router(api_router, prefix="/api")
    app.include_router(ws_router)

    return app


app = create_app()

__all__ = ["app", "create_app"]
