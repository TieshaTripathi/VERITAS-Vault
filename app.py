"""Vercel FastAPI entrypoint. Local: python -m uvicorn app:app --port 8502."""
from dotenv import load_dotenv
load_dotenv(override=False)

from src.pwa.api import app  # noqa: E402,F401
