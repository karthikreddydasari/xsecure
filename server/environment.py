"""
server/environment.py — xsecure incident response simulation.
Extends openenv-core Environment base class correctly.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

try:
    from openenv_core.env_server import Environment
except ImportError:
    from core.env_server import Environment

from models import (
    ActionType,
    IncidentAction,
    IncidentObservation,
    IncidentState,
)

# ---------------------------------------------------------------------------
# Task definitions
# ---------------------------------------------------------------------------

TASKS: Dict[int, dict] = {
    1: {
        "attack_type":    "brute_force",
        "attacker_ip":    "192.168.1.47",
        "target_user":    "admin",
        "target_service": "auth-service",
        "max_steps":      12,
        "logs": [
            {"log_id": "L001", "message": "Multiple failed login attempts from 192.168.1.47 (47 attempts in 60s)", "timestamp": "2024-01-15T08:01:00Z"},
            {"log_id": "L002", "message": "Account lockout triggered for user admin after failed logins from 192.168.1.47", "timestamp": "2024-01-15T08:01:45Z"},
            {"log_id": "L003", "message": "Successful login from 192.168.1.47 after lockout bypass", "timestamp": "2024-01-15T08:03:10Z"},
        ],
        "alerts": [
            {"alert_id": "A001", "message": "Brute force pattern detected — 47 failed logins in 60 seconds", "severity": "high"},
            {"alert_id": "A002", "message": "Account lockout bypass attempt detected", "severity": "high"},
        ],
        "services": [
            {"name": "auth-service", "status": "degraded"},
            {"name": "web-app",      "status": "running"},
            {"name": "database",     "status": "running"},
        ],
        "active_users": ["admin", "alice", "bob"],
        "correct_sequence": {
            "analyze_log:L001":       0.15,
            "analyze_log:L002":       0.15,
            "block_ip:192.168.1.47":  0.50,
        },
        "wrong_penalty":          -0.15,
        "delay_penalty":           0.05,
        "speed_bonus_threshold":   6,
        "speed_bonus":             0.20,
        "compromise_steps":        8,
    },
    2: {
        "attack_type":    "suspicious_login",
        "attacker_ip":    "203.0.113.55",
        "target_user":    "carol",
        "target_service": "hr-portal",
        "max_steps":      14,
        "logs": [
            {"log_id": "L001", "message": "Login for carol from unusual geo-location (203.0.113.55 — Eastern Europe)", "timestamp": "2024-01-15T14:22:00Z"},
            {"log_id": "L002", "message": "carol accessed sensitive HR records 3 minutes after login", "timestamp": "2024-01-15T14:25:10Z"},
            {"log_id": "L003", "message": "carol attempted to export 1,200 employee records", "timestamp": "2024-01-15T14:27:33Z"},
        ],
        "alerts": [
            {"alert_id": "A001", "message": "Login from unusual location for carol", "severity": "medium"},
            {"alert_id": "A002", "message": "Unusual data access pattern — bulk HR record access", "severity": "high"},
        ],
        "services": [
            {"name": "hr-portal",    "status": "running"},
            {"name": "auth-service", "status": "running"},
            {"name": "database",     "status": "running"},
        ],
        "active_users": ["carol", "dave", "alice"],
        "correct_sequence": {
            "analyze_log:L001":      0.10,
            "analyze_log:L002":      0.10,
            "trace_user:carol":      0.20,
            "disable_account:carol": 0.45,
        },
        "wrong_penalty":         -0.15,
        "delay_penalty":          0.05,
        "speed_bonus_threshold":  7,
        "speed_bonus":            0.15,
        "compromise_steps":       10,
    },
    3: {
        "attack_type":    "multi_stage",
        "attacker_ip":    "198.51.100.23",
        "target_user":    "eve",
        "target_service": "database",
        "max_steps":      18,
        "logs": [
            {"log_id": "L001", "message": "Phishing email link clicked by eve — redirect to 198.51.100.23", "timestamp": "2024-01-15T09:00:00Z"},
            {"log_id": "L002", "message": "Credential theft tool executed on eve's workstation", "timestamp": "2024-01-15T09:15:22Z"},
            {"log_id": "L003", "message": "eve authenticated to database server outside normal hours", "timestamp": "2024-01-15T09:22:45Z"},
            {"log_id": "L004", "message": "Lateral movement: eve's credentials used on prod-01 and database", "timestamp": "2024-01-15T09:30:11Z"},
            {"log_id": "L005", "message": "Ransomware staging detected on database — encryption not yet started", "timestamp": "2024-01-15T09:45:00Z"},
        ],
        "alerts": [
            {"alert_id": "A001", "message": "Phishing link accessed — possible credential compromise for eve", "severity": "medium"},
            {"alert_id": "A002", "message": "Credential harvesting tool detected", "severity": "high"},
            {"alert_id": "A003", "message": "Lateral movement across prod-01 and database", "severity": "high"},
        ],
        "services": [
            {"name": "database", "status": "degraded"},
            {"name": "prod-01",  "status": "degraded"},
            {"name": "web-app",  "status": "running"},
        ],
        "active_users": ["eve", "frank", "grace"],
        "correct_sequence": {
            "analyze_log:L001":         0.08,
            "analyze_log:L002":         0.08,
            "analyze_log:L004":         0.08,
            "trace_user:eve":           0.12,
            "block_ip:198.51.100.23":   0.20,
            "disable_account:eve":      0.20,
            "restart_service:database": 0.12,
            "restart_service:prod-01":  0.12,
        },
        "wrong_penalty":         -0.10,
        "delay_penalty":          0.04,
        "speed_bonus_threshold":  10,
        "speed_bonus":            0.10,
        "compromise_steps":       12,
    },
}


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

class IncidentEnvironment(Environment):

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self):
        super().__init__()
        self._state: Optional[IncidentState] = None
        self._task_def: Optional[dict] = None

    # ---- openenv-core interface -----------------------------------------

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> IncidentObservation:
        task_id = int(kwargs.get("task_id", 1))
        if task_id not in TASKS:
            task_id = 1

        td = TASKS[task_id]
        self._task_def = td
        self._state = IncidentState(
            episode_id=episode_id or str(uuid.uuid4()),
            task_id=task_id,
            step_count=0,
            max_steps=td["max_steps"],
            attack_type=td["attack_type"],
            attacker_ip=td["attacker_ip"],
            target_user=td["target_user"],
            target_service=td["target_service"],
        )
        return self._build_observation("Episode started. Investigate the alerts and logs.")

    def step(
        self,
        action: IncidentAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> IncidentObservation:
        if self._state is None:
            raise RuntimeError("Call reset() before step().")

        state = self._state
        td    = self._task_def

        if state.done:
            return self._build_observation("Episode already finished.", reward=0.0)

        state.step_count += 1
        action_key = f"{action.action_type}:{action.target}"
        reward     = 0.0
        result_msg = ""

        # Delay penalty every step
        reward -= td["delay_penalty"]

        atype = action.action_type

        if atype == ActionType.ANALYZE_LOG:
            r, result_msg = self._handle_analyze_log(action.target, action_key)
            reward += r
        elif atype == ActionType.TRACE_USER:
            r, result_msg = self._handle_trace_user(action.target, action_key)
            reward += r
        elif atype == ActionType.BLOCK_IP:
            r, result_msg = self._handle_block_ip(action.target, action_key)
            reward += r
        elif atype == ActionType.DISABLE_ACCOUNT:
            r, result_msg = self._handle_disable_account(action.target, action_key)
            reward += r
        elif atype == ActionType.RESTART_SERVICE:
            r, result_msg = self._handle_restart_service(action.target, action_key)
            reward += r
        elif atype == ActionType.IGNORE:
            state.progress_level = min(state.progress_level + 1, state.max_progress)
            reward -= 0.10
            result_msg = "No action taken. Attack progresses!"
        else:
            state.wrong_actions += 1
            reward += td["wrong_penalty"]
            result_msg = f"Unknown action: {atype}"

        reward = round(reward, 4)
        state.total_reward += reward

        done, info = self._check_termination()
        if done:
            state.done = True

        return self._build_observation(result_msg, reward=reward, done=done, info=info)

    @property
    def state(self) -> IncidentState:
        if self._state is None:
            raise RuntimeError("Call reset() first.")
        return self._state

    # ---- Action handlers -----------------------------------------------

    def _handle_analyze_log(self, target: str, key: str):
        state = self._state
        td    = self._task_def
        log_ids = [l["log_id"] for l in td["logs"]]

        if target not in log_ids:
            state.wrong_actions += 1
            return td["wrong_penalty"], f"Log {target} does not exist."
        if target in state.revealed_logs:
            return -0.05, f"Log {target} already analyzed."

        state.revealed_logs.append(target)
        if key in td["correct_sequence"]:
            state.correct_detections += 1
            msg = next(l["message"] for l in td["logs"] if l["log_id"] == target)
            return td["correct_sequence"][key], f"[ANALYSIS] {target}: {msg}"
        return 0.05, f"Log {target} analyzed — no significant findings."

    def _handle_trace_user(self, target: str, key: str):
        state = self._state
        td    = self._task_def

        if target not in td["active_users"]:
            state.wrong_actions += 1
            return td["wrong_penalty"], f"User {target!r} not found."
        if target in state.revealed_users:
            return -0.05, f"User {target} already traced."

        state.revealed_users.append(target)
        if key in td["correct_sequence"]:
            state.correct_detections += 1
            return td["correct_sequence"][key], f"[TRACE] {target}: Confirmed suspicious activity."
        return 0.05, f"User {target} traced — activity appears normal."

    def _handle_block_ip(self, target: str, key: str):
        state = self._state
        td    = self._task_def

        if target in state.blocked_ips:
            return -0.05, f"IP {target} already blocked."
        state.blocked_ips.append(target)

        if key in td["correct_sequence"]:
            state.correct_detections += 1
            multiplier = 1.0 if state.correct_detections > 1 else 0.6
            return td["correct_sequence"][key] * multiplier, f"[BLOCKED] IP {target} blocked."
        state.wrong_actions += 1
        return td["wrong_penalty"], f"Blocking {target} was incorrect."

    def _handle_disable_account(self, target: str, key: str):
        state = self._state
        td    = self._task_def

        if target in state.disabled_accounts:
            return -0.05, f"Account {target} already disabled."
        state.disabled_accounts.append(target)

        if key in td["correct_sequence"]:
            state.correct_detections += 1
            multiplier = 1.0 if state.correct_detections > 1 else 0.6
            return td["correct_sequence"][key] * multiplier, f"[DISABLED] Account {target} disabled."
        state.wrong_actions += 1
        return td["wrong_penalty"], f"Disabling {target} was incorrect."

    def _handle_restart_service(self, target: str, key: str):
        state = self._state
        td    = self._task_def

        valid = [s["name"] for s in td["services"]]
        if target not in valid:
            state.wrong_actions += 1
            return td["wrong_penalty"], f"Service {target!r} not found."
        if target in state.restarted_services:
            return -0.05, f"Service {target} already restarted."

        state.restarted_services.append(target)
        if key in td["correct_sequence"]:
            state.correct_detections += 1
            return td["correct_sequence"][key], f"[RESTARTED] Service {target} restored."
        state.wrong_actions += 1
        return td["wrong_penalty"], f"Restarting {target} was not necessary."

    # ---- Termination ---------------------------------------------------

    def _check_termination(self):
        state = self._state
        td    = self._task_def
        seq   = td["correct_sequence"]

        all_done = all(self._action_completed(k) for k in seq)

        speed_bonus = 0.0
        if all_done and state.step_count <= td["speed_bonus_threshold"]:
            speed_bonus = td["speed_bonus"]
            state.total_reward += speed_bonus

        compromise = (
            state.progress_level >= state.max_progress
            or state.step_count >= td["compromise_steps"]
        ) and not all_done

        timeout = state.step_count >= state.max_steps
        done    = all_done or compromise or timeout

        if done:
            state.success   = all_done and not compromise
            state.compromise = compromise

        max_possible = sum(seq.values()) + td["speed_bonus"]
        final_score  = round(min(max(state.total_reward, 0.0) / max_possible, 1.0), 4) if max_possible > 0 else 0.0

        info = {
            "final_score":   final_score,
            "success":       state.success,
            "compromise":    state.compromise,
            "wrong_actions": state.wrong_actions,
            "speed_bonus":   speed_bonus,
        } if done else {}

        return done, info

    def _action_completed(self, key: str) -> bool:
        action_type, target = key.split(":", 1)
        s = self._state
        return {
            "analyze_log":     target in s.revealed_logs,
            "trace_user":      target in s.revealed_users,
            "block_ip":        target in s.blocked_ips,
            "disable_account": target in s.disabled_accounts,
            "restart_service": target in s.restarted_services,
        }.get(action_type, False)

    # ---- Observation builder -------------------------------------------

    def _build_observation(
        self,
        result_msg: str,
        reward: float = 0.0,
        done: bool = False,
        info: dict = None,
    ) -> IncidentObservation:
        td = self._task_def
        return IncidentObservation(
            logs=td["logs"],
            alerts=td["alerts"],
            services=td["services"],
            active_users=td["active_users"],
            step_count=self._state.step_count,
            reward=reward,
            done=done,
            info=info or {},
            last_action_result=result_msg,
        )
