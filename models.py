"""
models.py — xsecure typed models.
All classes extend openenv-core Pydantic base classes correctly.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import Field

try:
    from openenv_core.env_server import Action, Observation, State
except ImportError:
    from core.env_server import Action, Observation, State


# ---------------------------------------------------------------------------
# Action space
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    ANALYZE_LOG     = "analyze_log"
    TRACE_USER      = "trace_user"
    BLOCK_IP        = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    RESTART_SERVICE = "restart_service"
    IGNORE          = "ignore"


class IncidentAction(Action):
    """
    One action the agent can take per step.
    Inherits from openenv-core Action (Pydantic BaseModel, extra='forbid').
    Note: 'metadata' field is inherited from Action base class.
    """
    action_type: str = Field(default="ignore", description="Action type to perform")
    target:      str = Field(default="",       description="Target of the action")


# ---------------------------------------------------------------------------
# Observation sub-models — use State base (extra='allow') for flexibility
# ---------------------------------------------------------------------------

class LogEntry(State):
    log_id:    str = ""
    message:   str = ""
    timestamp: str = ""


class AlertEntry(State):
    alert_id:  str = ""
    message:   str = ""
    severity:  str = "low"


class ServiceStatus(State):
    name:   str = ""
    status: str = "running"


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------

class IncidentObservation(Observation):
    """
    Everything the agent sees at each step.
    Inherits from openenv-core Observation (Pydantic BaseModel, extra='forbid').
    Note: 'done', 'reward', 'metadata' are inherited from Observation.
    """
    logs:               List[Dict[str, Any]] = Field(default_factory=list)
    alerts:             List[Dict[str, Any]] = Field(default_factory=list)
    services:           List[Dict[str, Any]] = Field(default_factory=list)
    active_users:       List[str]            = Field(default_factory=list)
    step_count:         int                  = 0
    info:               Dict[str, Any]       = Field(default_factory=dict)
    last_action_result: str                  = ""


# ---------------------------------------------------------------------------
# State — internal server state, never sent to agent directly
# ---------------------------------------------------------------------------

class IncidentState(State):
    """
    Full internal episode state.
    Inherits from openenv-core State (Pydantic BaseModel, extra='allow').
    All fields have defaults so IncidentState() works with no arguments.
    """
    task_id:            int        = 1
    max_steps:          int        = 15
    attack_type:        str        = "brute_force"
    attacker_ip:        str        = ""
    target_user:        str        = ""
    target_service:     str        = "auth-service"
    progress_level:     int        = 0
    max_progress:       int        = 4
    revealed_logs:      List[str]  = Field(default_factory=list)
    revealed_users:     List[str]  = Field(default_factory=list)
    blocked_ips:        List[str]  = Field(default_factory=list)
    disabled_accounts:  List[str]  = Field(default_factory=list)
    restarted_services: List[str]  = Field(default_factory=list)
    correct_detections: int        = 0
    wrong_actions:      int        = 0
    total_reward:       float      = 0.0
    success:            bool       = False
    compromise:         bool       = False
    stage:              int        = 1
    phishing_done:      bool       = False
    escalation_done:    bool       = False
