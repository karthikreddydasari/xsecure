"""
inference.py — OpenEnv-compliant inference script for xsecure.

Required env vars (set in .env for local dev, HF Secrets for production):
    HF_TOKEN       Hugging Face / API key
    API_BASE_URL   LLM endpoint
    MODEL_NAME     Model identifier

STDOUT FORMAT (machine-parsed by evaluator):
    [START] task=<name> env=xsecure model=<model>
    [STEP]  step=<n> action=<str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<0.000> rewards=<r1,r2,...>
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from typing import Dict, List, Optional

from dotenv import load_dotenv
from openai import OpenAI

from client import IncidentResponseEnv, StepResult
from models import IncidentAction, IncidentObservation

# Load .env for local dev (no-op when running on HF Spaces with Secrets)
load_dotenv()

# ---------------------------------------------------------------------------
# Configuration — all from environment variables
# ---------------------------------------------------------------------------

API_KEY      = os.getenv("HF_TOKEN") or os.getenv("API_KEY", "")
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
ENV_URL      = os.getenv("ENV_URL", "http://localhost:7860")
BENCHMARK    = "xsecure"
MAX_STEPS    = 20

if not API_KEY:
    print("ERROR: HF_TOKEN is not set.", file=sys.stderr)
    sys.exit(1)

llm = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

# ---------------------------------------------------------------------------
# Mandatory stdout loggers
# ---------------------------------------------------------------------------

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} "
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
You will be given the current state of a simulated company under cyber attack.
Your goal is to investigate logs and alerts, identify the threat, and mitigate it.

## Available Actions (one per step):
- analyze_log(log_id)      — Examine a specific log entry
- trace_user(user_id)      — Investigate a user's activity history
- block_ip(ip_address)     — Block a suspicious IP address
- disable_account(user_id) — Disable a compromised user account
- restart_service(service) — Restart a compromised service
- ignore                   — Take no action (penalised!)

## Response Format (STRICT — machine-parsed):
{"action_type": "analyze_log", "target": "L001"}

## Strategy:
1. Investigate first (analyze_log, trace_user) to gather evidence.
2. Act decisively once you have evidence (block_ip, disable_account, restart_service).
3. Never block/disable without evidence — wrong actions cost points.
4. Speed matters — faster resolution earns a bonus.
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_observation(obs: IncidentObservation) -> str:
    logs_txt     = "\n".join(f"  [{l['log_id']}] {l['timestamp']} — {l['message']}" for l in obs.logs)
    alerts_txt   = "\n".join(f"  [{a['severity'].upper()}] {a['message']}" for a in obs.alerts)
    services_txt = "\n".join(f"  {s['name']}: {s['status']}" for s in obs.services)
    return (
        f"=== Incident Dashboard (Step {obs.step_count}) ===\n\n"
        f"LOGS:\n{logs_txt}\n\n"
        f"ALERTS:\n{alerts_txt}\n\n"
        f"SERVICES:\n{services_txt}\n\n"
        f"ACTIVE USERS: {', '.join(obs.active_users)}\n\n"
        f"Last action result: {obs.last_action_result}"
    )


def _parse_action(text: str) -> IncidentAction:
    for pattern in [
        lambda t: json.loads(t.strip()),
        lambda t: json.loads(re.search(r"```(?:json)?\s*(\{.*?\})\s*```", t, re.DOTALL).group(1)),
        lambda t: json.loads(re.search(r"\{[^{}]+\}", t).group(0)),
    ]:
        try:
            return IncidentAction(**pattern(text))
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

TASK_NAMES = {
    1: "brute-force-easy",
    2: "suspicious-login-medium",
    3: "multi-stage-apt-hard",
}

async def run_episode(task_id: int) -> None:
    task_name  = TASK_NAMES[task_id]
    rewards:   List[float] = []
    steps_taken = 0
    success    = False
    score      = 0.0
    conversation: List[Dict] = []

    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

    try:
        async with IncidentResponseEnv(base_url=ENV_URL) as env:
            obs = await env.reset(task_id=task_id)

            for step in range(1, MAX_STEPS + 1):
                action = _get_action(conversation, obs)
                result = await env.step(action)

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
                    info  = result.info
                    score = min(max(float(info.get("final_score", 0.0)), 0.0), 1.0)
                    success = bool(info.get("success", False))
                    break

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    task_ids = [int(t) for t in os.getenv("TASK_IDS", "1,2,3").split(",")]
    for task_id in task_ids:
        await run_episode(task_id)

if __name__ == "__main__":
    asyncio.run(main())
