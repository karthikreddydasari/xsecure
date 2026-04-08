"""
graders.py — Agent graders for the xsecure Incident Response environment.
Each grader runs a full episode and returns a normalised score 0.0–1.0.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Dict, List, Optional

from client import IncidentResponseEnv, StepResult
from models import IncidentAction, IncidentObservation


# ---------------------------------------------------------------------------
# Grader result
# ---------------------------------------------------------------------------

class GradeResult:
    def __init__(
        self,
        task_id:       int,
        score:         float,
        success:       bool,
        compromise:    bool,
        steps_taken:   int,
        wrong_actions: int,
        notes:         str = "",
    ):
        self.task_id       = task_id
        self.score         = score
        self.success       = success
        self.compromise    = compromise
        self.steps_taken   = steps_taken
        self.wrong_actions = wrong_actions
        self.notes         = notes

    def __repr__(self):
        status = "✅ SUCCESS" if self.success else ("❌ COMPROMISED" if self.compromise else "⏱ TIMEOUT")
        return (
            f"GradeResult(task={self.task_id}, score={self.score:.3f}, "
            f"status={status}, steps={self.steps_taken}, wrong={self.wrong_actions})"
        )


# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------

async def _run_episode(
    base_url:  str,
    task_id:   int,
    agent_fn:  Callable[[IncidentObservation, List[StepResult]], IncidentAction],
    max_steps: int = 20,
    seed:      Optional[int] = None,
) -> GradeResult:
    """Run one full episode driven by agent_fn."""
    history: List[StepResult] = []
    last_result: Optional[StepResult] = None

    async with IncidentResponseEnv(base_url=base_url) as env:
        obs = await env.reset(task_id=task_id)

        for _ in range(max_steps):
            action = agent_fn(obs, history)
            result = await env.step(action)
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
# Public grade function
# ---------------------------------------------------------------------------

async def grade(
    agent_fn:     Callable[[IncidentObservation, List[StepResult]], IncidentAction],
    task_id:      int,
    base_url:     str = "http://localhost:7860",
    num_episodes: int = 3,
) -> Dict:
    """
    Run num_episodes of task_id and return aggregate stats.

    Returns
    -------
    dict with keys: task_id, mean_score, min_score, max_score, success_rate, episodes
    """
    results = []
    for ep in range(num_episodes):
        seed = ep * 1000 + task_id if num_episodes > 1 else None
        r = await _run_episode(base_url, task_id, agent_fn, seed=seed)
        results.append(r)

    scores = [r.score for r in results]
    return {
        "task_id":      task_id,
        "mean_score":   round(sum(scores) / len(scores), 4),
        "min_score":    round(min(scores), 4),
        "max_score":    round(max(scores), 4),
        "success_rate": round(sum(1 for r in results if r.success) / len(results), 4),
        "episodes":     [repr(r) for r in results],
    }


# ---------------------------------------------------------------------------
# Oracle agents (deterministic, for reproducible baseline scores)
# ---------------------------------------------------------------------------

def _oracle_task1(obs: IncidentObservation, history: List[StepResult]) -> IncidentAction:
    sequence = [
        IncidentAction(action_type="analyze_log", target="L001"),
        IncidentAction(action_type="analyze_log", target="L002"),
        IncidentAction(action_type="block_ip",    target="192.168.1.47"),
    ]
    return sequence[obs.step_count] if obs.step_count < len(sequence) else IncidentAction(action_type="ignore")


def _oracle_task2(obs: IncidentObservation, history: List[StepResult]) -> IncidentAction:
    sequence = [
        IncidentAction(action_type="analyze_log",     target="L001"),
        IncidentAction(action_type="analyze_log",     target="L002"),
        IncidentAction(action_type="trace_user",      target="carol"),
        IncidentAction(action_type="disable_account", target="carol"),
    ]
    return sequence[obs.step_count] if obs.step_count < len(sequence) else IncidentAction(action_type="ignore")


def _oracle_task3(obs: IncidentObservation, history: List[StepResult]) -> IncidentAction:
    sequence = [
        IncidentAction(action_type="analyze_log",     target="L001"),
        IncidentAction(action_type="analyze_log",     target="L002"),
        IncidentAction(action_type="analyze_log",     target="L004"),
        IncidentAction(action_type="trace_user",      target="eve"),
        IncidentAction(action_type="block_ip",        target="198.51.100.23"),
        IncidentAction(action_type="disable_account", target="eve"),
        IncidentAction(action_type="restart_service", target="database"),
        IncidentAction(action_type="restart_service", target="prod-01"),
    ]
    return sequence[obs.step_count] if obs.step_count < len(sequence) else IncidentAction(action_type="ignore")


ORACLE_AGENTS = {1: _oracle_task1, 2: _oracle_task2, 3: _oracle_task3}


# ---------------------------------------------------------------------------
# CLI — grade all oracle agents
# ---------------------------------------------------------------------------

async def _grade_all(base_url: str):
    print("=" * 60)
    print("xsecure — Grading Oracle Agents")
    print("=" * 60)
    for task_id in [1, 2, 3]:
        result = await grade(ORACLE_AGENTS[task_id], task_id, base_url, num_episodes=3)
        print(f"\nTask {task_id}: mean_score={result['mean_score']:.4f}  "
              f"success_rate={result['success_rate']:.2%}")
        for ep in result["episodes"]:
            print(f"  {ep}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:7860")
    args = parser.parse_args()
    asyncio.run(_grade_all(args.url))
