"""
client.py — xsecure environment client.

Usage (async):
    async with IncidentResponseEnv(base_url="http://localhost:7860") as env:
        obs = await env.reset(task_id=1)
        result = await env.step(IncidentAction(action_type="analyze_log", target="L001"))

Usage (sync):
    with IncidentResponseEnv(base_url="http://localhost:7860").sync() as env:
        obs = env.reset(task_id=1)
        result = env.step(IncidentAction(action_type="analyze_log", target="L001"))
"""

from __future__ import annotations

from typing import Any, Dict

try:
    from openenv_core import EnvClient
    from openenv_core.types import StepResult
except ImportError:
    from openenv_core import EnvClient
    from openenv_core import *

from models import IncidentAction, IncidentObservation, IncidentState


class IncidentResponseEnv(EnvClient[IncidentAction, IncidentObservation]):
    """
    Client for the xsecure Incident Response environment.
    Inherits reset(), step(), state(), sync(), from_hub(), from_docker_image()
    from openenv-core's HTTPEnvClient.
    """

    def _step_payload(self, action: IncidentAction) -> Dict[str, Any]:
        """Serialize action to JSON for the /step endpoint."""
        return {
            "action_type": action.action_type,
            "target":      action.target,
        }

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult:
        """Deserialize HTTP response into a typed StepResult."""
        obs_data = payload.get("observation", {})

        # logs/alerts/services are stored as List[Dict] in IncidentObservation
        obs = IncidentObservation(
            logs=obs_data.get("logs", []),
            alerts=obs_data.get("alerts", []),
            services=obs_data.get("services", []),
            active_users=obs_data.get("active_users", []),
            step_count=obs_data.get("step_count", 0),
            reward=obs_data.get("reward", 0.0),
            done=obs_data.get("done", False),
            info=obs_data.get("info", {}),
            last_action_result=obs_data.get("last_action_result", ""),
        )

        return StepResult(
            observation=obs,
            reward=payload.get("reward", 0.0),
            done=payload.get("done", False),
            info=payload.get("info", {}),
        )

    def _parse_state(self, payload: Dict[str, Any]) -> IncidentState:
        """Deserialize /state response into IncidentState."""
        data = payload.get("state", payload)
        # IncidentState is Pydantic — use model_fields for field names
        valid_fields = set(IncidentState.model_fields.keys())
        return IncidentState(**{k: v for k, v in data.items() if k in valid_fields})


__all__ = ["IncidentResponseEnv", "StepResult"]
