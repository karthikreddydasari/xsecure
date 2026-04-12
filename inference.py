"""
inference.py — OpenEnv-compliant inference script for xsecure.

Required env vars:
    HF_TOKEN       Hugging Face / API key
    API_BASE_URL   LLM endpoint
    MODEL_NAME     Model identifier
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from typing import Dict, List, Optional, Any

from dotenv import load_dotenv
from openai import OpenAI

from client import IncidentResponseEnv, StepResult
from models import IncidentAction, IncidentObservation

# Load .env for local dev
load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
"""
API_KEY      = os.getenv("API_KEY", "")
API_BASE_URL = os.getenv("API_BASE_URL")
MODEL_NAME   = os.getenv("MODEL_NAME")
ENV_URL      = os.getenv("ENV_URL", "http://localhost:7860")
BENCHMARK    = "xsecure"
MAX_STEPS    = 20
"""

API_BASE_URL = os.environ.get("API_BASE_URL",  "https://api.openai.com/v1")
MODEL_NAME   = os.environ.get("MODEL_NAME",  "gpt-4o-mini")
API_KEY      = os.environ.get("API_KEY", "")
ENV_URL      = os.environ.get("ENV_URL", "http://localhost:7860")

BENCHMARK    = "xsecure"
MAX_STEPS    = 20

if not API_KEY:
    print("ERROR: HF_TOKEN is not set.", file=sys.stderr)
    sys.exit(1)

# Use AsyncOpenAI to prevent blocking the event loop
llm = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

# ---------------------------------------------------------------------------
# Mandatory stdout loggers (Fixed spacing to match spec)
# ---------------------------------------------------------------------------

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    # Spec requires double space after [STEP] for some parsers
    print(
        f"[STEP]  step={step} action={action} reward={reward:.2f} "
        f"done={str(done).lower()} error={error or 'null'}",
        flush=True,
    )

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} "
        f"rewards={','.join(f'{r:.2f}' for r in rewards)}",
        flush=True,
    )

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert cybersecurity incident responder AI agent.
Your goal is to investigate logs and alerts, identify the threat, and mitigate it.

## Available Actions (one per step):
- analyze_log(log_id)
- trace_user(user_id)
- block_ip(ip_address)
- disable_account(user_id)
- restart_service(service)
- ignore

## Response Format (STRICT JSON):
{"action_type": "analyze_log", "target": "L001"}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_observation(obs: IncidentObservation) -> str:
    # Use dot notation as expected by the environment models
    logs_txt     = "\n".join(f"  [{l.log_id}] {l.timestamp} — {l.message}" for l in obs.logs)
    alerts_txt   = "\n".join(f"  [{a.severity.upper()}] {a.message}" for a in obs.alerts)
    services_txt = "\n".join(f"  {s.name}: {s.status}" for s in obs.services)
    
    return (
        f"=== Incident Dashboard (Step {obs.step_count}) ===\n\n"
        f"LOGS:\n{logs_txt}\n\n"
        f"ALERTS:\n{alerts_txt}\n\n"
        f"SERVICES:\n{services_txt}\n\n"
        f"ACTIVE USERS: {', '.join(obs.active_users)}\n\n"
        f"Last action result: {obs.last_action_result}"
    )

def _parse_action(text: str) -> IncidentAction:
    """Extract JSON action with filtering for extra fields to avoid Pydantic errors."""
    try:
        # 1. Try direct or markdown-wrapped JSON
        pattern = re.search(r"(\{.*?\})", text.strip().replace("\n", " "), re.DOTALL)
        if pattern:
            data = json.loads(pattern.group(1))
            # Only pass fields known to IncidentAction
            valid_keys = {"action_type", "target"}
            filtered = {k: v for k, v in data.items() if k in valid_keys}
            return IncidentAction(**filtered)
    except Exception:
        pass
    return IncidentAction(action_type="ignore", target="")

def _get_action(conversation: List[Dict], obs: IncidentObservation) -> IncidentAction:
    conversation.append({"role": "user", "content": _format_observation(obs)})
    
    response = llm.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "system", "content": SYSTEM_PROMPT}] + conversation,
        max_tokens=256,
        temperature=0.0,
    )
    
    text = response.choices[0].message.content or ""
    conversation.append({"role": "assistant", "content": text})
    return _parse_action(text)

# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------

TASK_NAMES = {1: "brute-force-easy", 2: "suspicious-login-medium", 3: "multi-stage-apt-hard"}

def run_episode(task_id: int) -> None:
    task_name = TASK_NAMES.get(task_id, f"task-{task_id}")
    rewards: List[float] = []
    steps_taken = 0
    success = False
    score = 0.0
    conversation: List[Dict] = []

    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

    try:
        with IncidentResponseEnv(base_url=ENV_URL) as env:
            obs = env.reset(task_id=task_id)

            for step in range(1, MAX_STEPS + 1):
                # Now awaited correctly
                action = _get_action(conversation, obs)
                result = env.step(action)

                rewards.append(result.reward)
                steps_taken = step
                obs = result.observation

                log_step(
                    step=step,
                    action=f"{action.action_type}({action.target!r})",
                    reward=result.reward,
                    done=result.done,
                    error=None,
                )

                if result.done:
                    info = result.info or {}
                    # Robust score parsing
                    raw_score = info.get("final_score", 0.0)
                    score = min(max(float(raw_score or 0.0), 0.0), 1.0)
                    success = bool(info.get("success", False))
                    break
    except Exception as e:
        print(f"ERROR: Episode failed: {e}", file=sys.stderr)
    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    task_ids_str = os.getenv("TASK_IDS", "1,2,3")
    task_ids = [int(t.strip()) for t in task_ids_str.split(",") if t.strip()]
    for task_id in task_ids:
        run_episode(task_id)

if __name__ == "__main__":
    main()
