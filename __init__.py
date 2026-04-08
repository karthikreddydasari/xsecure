"""
xsecure — Autonomous Incident Response & Threat Mitigation Environment.
OpenEnv-compatible package.

Quick start
-----------
    from xsecure import IncidentResponseEnv, IncidentAction

    async with IncidentResponseEnv(base_url="http://localhost:7860") as env:
        obs = await env.reset(task_id=1)
        result = await env.step(IncidentAction(action_type="analyze_log", target="L001"))

    # Or let openenv-core manage Docker for you:
    env = await IncidentResponseEnv.from_docker_image("xsecure:latest")
"""

from client import IncidentResponseEnv, StepResult          # noqa: F401
from models import (                                          # noqa: F401
    IncidentAction,
    IncidentObservation,
    IncidentState,
    ActionType,
)

__version__ = "1.0.0"
__all__ = [
    "IncidentResponseEnv",
    "StepResult",
    "IncidentAction",
    "IncidentObservation",
    "IncidentState",
    "ActionType",
]
