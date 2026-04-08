from __future__ import annotations
from typing import Any, Dict

# Standard OpenEnv imports
from openenv_core import EnvClient 
from openenv_core.client_types import StepResult

from models import IncidentAction, IncidentObservation, IncidentState

class IncidentResponseEnv(EnvClient[IncidentAction, IncidentObservation, IncidentState]):
    """
    Client for the xsecure Incident Response environment.
    Inherits all core methods (reset, step, state) from HTTPEnvClient.
    """

    def _step_payload(self, action: IncidentAction) -> Dict[str, Any]:
        """Serialize action for the /step endpoint."""
        return {
            "action_type": action.action_type,
            "target":      action.target,
        }

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult:
        """Deserialize HTTP response into a typed StepResult."""
        obs_data = payload.get("observation", {})
        
        # Leverage Pydantic's ability to handle the dictionary directly
        obs = IncidentObservation(**obs_data)

        return StepResult(
            observation=obs,
            reward=payload.get("reward", 0.0),
            done=payload.get("done", False),
            #info=payload.get("info", {}),
        )

    def _parse_state(self, payload: Dict[str, Any]) -> IncidentState:
        """Deserialize /state response into IncidentState."""
        data = payload.get("state", payload)
        # Filters keys to match the Pydantic model fields
        valid_fields = set(IncidentState.model_fields.keys())
        return IncidentState(**{k: v for k, v in data.items() if k in valid_fields})
