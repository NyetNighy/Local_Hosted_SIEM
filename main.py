"""Alternative ASGI entrypoint wrapper with safe fallback mode.

Use `uvicorn main:app` for operational startup to avoid accidental local
merge-conflict breakage in `app.py`.
"""

import importlib

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

_application_module = None


def _fallback_startup_app(exc: Exception) -> FastAPI:
    fallback = FastAPI(title="CodexSIEM Startup Error")

    @fallback.get("/", response_class=PlainTextResponse)
    async def startup_error() -> str:
        return (
            "CodexSIEM failed to import application.py at startup.\n"
            f"Error: {exc}\n"
            "Recovery: run `python run_server.py --auto-recover --host 0.0.0.0 --port 8000`.\n"
        )
    return fallback


def _load_app() -> FastAPI:
    global _application_module  # noqa: PLW0603
    try:
        _application_module = importlib.import_module("application")
        return _application_module.app
    except Exception as exc:  # noqa: BLE001
        return _fallback_startup_app(exc)


def __getattr__(name: str):
    if _application_module is not None and hasattr(_application_module, name):
        return getattr(_application_module, name)
    raise AttributeError(name)


app = _load_app()

from application import *  # noqa: F401,F403
