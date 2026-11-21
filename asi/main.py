"""Punkt wejścia ASGI. Start: uvicorn asi.main:app --host 127.0.0.1 --port 8000"""
from .api import create_app

app = create_app()
