"""
Baseline inference script — uses OpenAI API client to run an LLM agent
against all 3 tasks and produces reproducible scores.

Usage
-----
    export OPENAI_API_KEY="sk-..."
    export ENV_URL="http://localhost:8000"   # optional, defaults to localhost
    python baseline.py

The script prints per-task and aggregate scores, then writes results to
baseline_results.json for reproducibility.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional

from openai import AsyncOpenAI

from client import IncidentResponseEnv, StepResult
from graders import GradeResult, grade
from models import IncidentAction, IncidentObservation

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_KEY = os.getenv("API_KEY", "")
ENV_URL        = os.getenv("API_BASE_URL", "http://localhost:8000")
MODEL_NAME     = os.getenv("BASELINE_MODEL", "gpt-4o-mini")
NUM_EPISODES   = int(os.getenv("NUM_EPISODES", "3"))

if not API_KEY:
    print("ERROR: API_KEY environment variable is not set.", file=sys.stderr)
    sys.exit(1)

client = AsyncOpenAI(api_key= API_KEY)

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert cybersecurity incident responder AI agent.
You will be given the current state of a simulated company under cyber attack.
Your goal is to investigate logs and alerts, identify the threat, and mitigate it before the system is compromised.

## Available Actions (one per step):
- analyze_log(log_id)      — Examine a specific log entry for more detail
- trace_user(user_id)      — Investigate a user's activity history
- block_ip(ip_address)     — Block a suspicious IP address
- disable_account(user_id) — Disable a compromised user account
- restart_service(service) — Restart a compromised or degraded service
- ignore                   — Take no action (penalised — attack progresses!)

## Response Format (STRICT — machine-parsed):
You MUST respond ONLY with a JSON object like:
{"action_type": "analyze_log", "target": "L001"}

Valid action_type values: analyze_log, trace_user, block_ip, disable_account, restart_service, ignore

## Strategy:
1. First investigate (analyze_log, trace_user) to gather evidence.
2. Then act decisively on confirmed threats (block_ip, disable_account, restart_service).
3. Never block/disable unless you have strong evidence — wrong actions cost points.
4. Speed matters — faster resolution earns a bonus.
"""

# ---------------------------------------------------------------------------
# LLM-driven agent
# ---------------------------------------------------------------------------

def _format_observation(obs: IncidentObservation) -> str:
    logs_txt    = "\n".join(f"  [{l.log_id}] {l.timestamp} — {l.message}" for l in obs.logs)
    alerts_txt  = "\n".join(f"  [{a.severity.upper()}] {a.message}" for a in obs.alerts)
    services_txt = "\n".join(f"  {s.name}: {s.status}" for s in obs.services)
    users_txt   = ", ".join(obs.active_users)

    return f"""\
=== Incident Response Dashboard (Step {obs.step_count}) ===

LOGS:
{logs_txt}

ALERTS:
{alerts_txt}

SERVICES:
{services_txt}

ACTIVE USERS: {users_txt}

Last action result: {obs.last_action_result}
"""


def _parse_llm_response(text: str) -> IncidentAction:
    """Extract JSON action from LLM output. Falls back to ignore on parse failure."""
    # Try direct JSON parse
    stripped = text.strip()
    try:
        data = json.loads(stripped)
        return IncidentAction(**data)
    except Exception:
        pass

    # Try extracting JSON from markdown code block
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(1))
            return IncidentAction(**data)
        except Exception:
            pass

    # Try finding raw JSON object in text
    match = re.search(r"\{[^{}]+\}", stripped)
    if match:
        try:
            data = json.loads(match.group(0))
            return IncidentAction(**data)
        except Exception:
            pass

    # Fallback
    print(f"  [WARN] Could not parse LLM output: {text[:120]!r} — defaulting to ignore")
    return IncidentAction(action_type="ignore", target="")


async def _llm_agent_fn(
    obs: IncidentObservation,
    history: List[StepResult],
    conversation: List[Dict],
) -> IncidentAction:
    """Call OpenAI API and return the next action."""
    user_msg = _format_observation(obs)

    conversation.append({"role": "user", "content": user_msg})

    response = await client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "system", "content": SYSTEM_PROMPT}] + conversation,
        max_tokens=256,
        temperature=0.0,  # deterministic for reproducibility
    )

    assistant_text = response.choices[0].message.content or ""
    conversation.append({"role": "assistant", "content": assistant_text})

    return _parse_llm_response(assistant_text)


# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------

async def _run_llm_episode(task_id: int) -> GradeResult:
    conversation: List[Dict] = []
    last_result: Optional[StepResult] = None

    async with IncidentResponseEnv(base_url=ENV_URL) as env:
        obs = await env.reset(task_id=task_id)
        history: List[StepResult] = []

        for step in range(25):  # safety cap
            action = await _llm_agent_fn(obs, history, conversation)
            print(f"    step {step + 1:02d}: {action.action_type}({action.target!r})", end="")

            result = await env.step(action)
            print(f"  → reward={result.reward:+.2f}")

            history.append(result)
            last_result = result
            obs = result.observation

            if result.done:
                break

    info = last_result.info if last_result else {}
    return GradeResult(
        task_id=task_id,
        score=float(info.get("final_score", 0.0)),
        success=bool(info.get("success", False)),
        compromise=bool(info.get("compromise", False)),
        steps_taken=obs.step_count,
        wrong_actions=int(info.get("wrong_actions", 0)),
        notes=obs.last_action_result,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 65)
    print(f"Incident Response Env — Baseline ({MODEL_NAME})")
    print(f"Environment: {ENV_URL}")
    print(f"Episodes per task: {NUM_EPISODES}")
    print("=" * 65)

    all_scores: List[float] = []
    output: Dict = {
        "model":        MODEL_NAME,
        "env_url":      ENV_URL,
        "timestamp":    datetime.utcnow().isoformat(),
        "tasks":        {},
    }

    for task_id in [1, 2, 3]:
        task_names = {
            1: "Brute Force (Easy)",
            2: "Suspicious Login (Medium)",
            3: "Multi-Stage APT (Hard)",
        }
        print(f"\n--- Task {task_id}: {task_names[task_id]} ---")

        episode_results = []
        for ep in range(NUM_EPISODES):
            print(f"  Episode {ep + 1}/{NUM_EPISODES}:")
            result = await _run_llm_episode(task_id)
            episode_results.append(result)
            print(f"  → {result}")

        scores = [r.score for r in episode_results]
        mean   = sum(scores) / len(scores)
        all_scores.extend(scores)

        output["tasks"][str(task_id)] = {
            "mean_score":   round(mean, 4),
            "success_rate": round(sum(1 for r in episode_results if r.success) / NUM_EPISODES, 4),
            "episodes":     [
                {"score": r.score, "success": r.success, "steps": r.steps_taken}
                for r in episode_results
            ],
        }
        print(f"  Task {task_id} mean score: {mean:.4f}")

    overall = sum(all_scores) / len(all_scores)
    output["overall_mean_score"] = round(overall, 4)

    print(f"\n{'=' * 65}")
    print(f"Overall mean score: {overall:.4f}")
    print("=" * 65)

    out_path = "baseline_results.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
