"""
inference.py — OpenEnv-compliant inference script for xsecure.

Required env vars (injected by hackathon LiteLLM proxy):
    API_BASE_URL   The API endpoint for the LLM
    MODEL_NAME     The model identifier to use for inference
    HF_TOKEN       Your Hugging Face / API key  (validator may also inject API_KEY)

STDOUT FORMAT (strictly required):
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<0.000> rewards=<r1,r2,...>
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Dict, List, Optional

from openai import OpenAI

from client import IncidentResponseEnv
from models import IncidentAction, IncidentObservation

# ---------------------------------------------------------------------------
# Configuration
# NOTE: Do NOT call load_dotenv() — it overrides the env vars injected by
# the validator's LiteLLM proxy and breaks the LLM Criteria Check.
# ---------------------------------------------------------------------------

# Follow official sample pattern: HF_TOKEN first, then API_KEY fallback
API_KEY      = os.getenv("HF_TOKEN") or os.getenv("API_KEY", "")
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
ENV_URL      = os.getenv("ENV_URL", "http://localhost:7860")
BENCHMARK    = "xsecure"
MAX_STEPS    = 20

if not API_KEY:
    print("ERROR: Neither HF_TOKEN nor API_KEY is set.", file=sys.stderr)
    sys.exit(1)

# Initialize OpenAI-compatible client pointing at the injected proxy
llm = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

# ---------------------------------------------------------------------------
# Mandatory stdout loggers — format must match spec EXACTLY
# ---------------------------------------------------------------------------

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    print(
        f"[STEP]  step={step} action={action} reward={reward:.2f} "
        f"done={str(done).lower()} error={error or 'null'}",
        flush=True,
    )

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"score={score:.3f} rewards={rewards_str}",
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

## Response Format (STRICT JSON, no extra text):
{"action_type": "analyze_log", "target": "L001"}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_observation(obs: IncidentObservation) -> str:
    logs_txt     = "\n".join(
        f"  [{l['log_id']}] {l['timestamp']} - {l['message']}" for l in obs.logs
    )
    alerts_txt   = "\n".join(
        f"  [{a['severity'].upper()}] {a['message']}" for a in obs.alerts
    )
    services_txt = "\n".join(
        f"  {s['name']}: {s['status']}" for s in obs.services
    )
    return (
        f"=== Incident Dashboard (Step {obs.step_count}) ===\n\n"
        f"LOGS:\n{logs_txt}\n\n"
        f"ALERTS:\n{alerts_txt}\n\n"
        f"SERVICES:\n{services_txt}\n\n"
        f"ACTIVE USERS: {', '.join(obs.active_users)}\n\n"
        f"Last action result: {obs.last_action_result}"
    )

def _parse_action(text: str) -> IncidentAction:
    """Extract JSON action; fallback to ignore on any parse failure."""
    try:
        pattern = re.search(r"(\{.*?\})", text.strip().replace("\n", " "), re.DOTALL)
        if pattern:
            data = json.loads(pattern.group(1))
            filtered = {k: v for k, v in data.items() if k in {"action_type", "target"}}
            return IncidentAction(**filtered)
    except Exception:
        pass
    return IncidentAction(action_type="ignore", target="")

def _get_action(conversation: List[Dict], obs: IncidentObservation) -> IncidentAction:
    """Call LLM synchronously and return parsed action."""
    conversation.append({"role": "user", "content": _format_observation(obs)})
    try:
        response = llm.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "system", "content": SYSTEM_PROMPT}] + conversation,
            max_tokens=256,
            temperature=0.0,
        )
        text = response.choices[0].message.content or ""
    except Exception as e:
        print(f"[WARN] LLM call failed: {e}", file=sys.stderr)
        text = ""
    conversation.append({"role": "assistant", "content": text})
    return _parse_action(text)

# ---------------------------------------------------------------------------
# Episode runner (sync — matches official sample pattern)
# ---------------------------------------------------------------------------

TASK_NAMES = {
    1: "brute-force-easy",
    2: "suspicious-login-medium",
    3: "multi-stage-apt-hard",
}

def run_episode(task_id: int) -> None:
    task_name  = TASK_NAMES.get(task_id, f"task-{task_id}")
    rewards:   List[float] = []
    steps_taken = 0
    success    = False
    score      = 0.0
    conversation: List[Dict] = []

    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

    try:
        with IncidentResponseEnv(base_url=ENV_URL) as env:
            obs = env.reset(task_id=task_id)

            for step in range(1, MAX_STEPS + 1):
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
                    info   = result.info or {}
                    raw    = info.get("final_score", 0.0)
                    score  = min(max(float(raw or 0.0), 0.0), 1.0)
                    success = bool(info.get("success", False))
                    break

    except Exception as e:
        print(f"ERROR: Episode failed: {e}", file=sys.stderr)
    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    task_ids_str = os.getenv("TASK_IDS", "1,2,3")
    task_ids = [int(t.strip()) for t in task_ids_str.split(",") if t.strip()]
    for task_id in task_ids:
        run_episode(task_id)

if __name__ == "__main__":
    main()
