"""
server/app.py — FastAPI server for xsecure.
Uses openenv-core's create_fastapi_app — all endpoints generated automatically.
"""

from __future__ import annotations

import os

try:
    from openenv_core.env_server import create_fastapi_app
except ImportError:
    from core.env_server import create_fastapi_app

from .environment import IncidentEnvironment
from models import IncidentAction, IncidentObservation   # ← required by create_fastapi_app

# Pass the CLASS (not an instance) plus action and observation classes
app = create_fastapi_app(IncidentEnvironment, IncidentAction, IncidentObservation)


def main():
    import uvicorn
    uvicorn.run(
        "server.app:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "7860")),
        workers=int(os.getenv("WORKERS", "4")),
    )


if __name__ == "__main__":
    main()
