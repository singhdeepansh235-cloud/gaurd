"""Vercel entrypoint for the FastAPI app."""

from sentinal_fuzz.web.app import app

application = app
