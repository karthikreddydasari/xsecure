# 🛡️ Autonomous Incident Response & Threat Mitigation Environment

> *An RL environment where agents investigate evolving cyber threats and take sequential actions to detect and mitigate attacks before system compromise.*

[![OpenEnv](https://img.shields.io/badge/OpenEnv-compatible-blue)](https://github.com/meta-pytorch/OpenEnv)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

---

## 🧠 Overview

This environment simulates a company's IT infrastructure under active cyber attack.
The agent acts as an autonomous SOC (Security Operations Center) analyst: it receives partial system logs and alerts, must investigate the incident through targeted actions, and mitigate the attack before the attacker achieves their objective.

Unlike log-classification tasks, this is a **multi-step sequential decision problem** where:
- The environment state evolves (attack progresses if ignored)
- The agent must *discover* hidden information through investigation before acting
- Wrong mitigation actions have real costs (legitimate users disrupted)
- Speed matters — faster resolution earns bonus reward

---

## 🔁 RL Loop

```
Observation (partial) → Action → Reward + New Observation → ... → Done
```

### Observation Space

| Field | Type | Description |
|-------|------|-------------|
| `logs` | `List[LogEntry]` | System log entries visible so far |
| `alerts` | `List[AlertEntry]` | Security alerts (severity: low/medium/high) |
| `services` | `List[ServiceStatus]` | Running services and their health |
| `active_users` | `List[str]` | Currently active user accounts |
| `step_count` | `int` | Current step number |
| `last_action_result` | `str` | Human-readable result of last action |

### Action Space

| Action | Target | Description |
|--------|--------|-------------|
| `analyze_log` | `log_id` (e.g. `"L001"`) | Deep-dive into a log entry; may reveal new logs |
| `trace_user` | `user_id` (e.g. `"carol"`) | Investigate user activity; may reveal anomalies |
| `block_ip` | `ip_address` | Block a suspicious IP |
| `disable_account` | `user_id` | Disable a compromised account |
| `restart_service` | `service_name` | Restart a compromised or degraded service |
| `ignore` | `""` | No action — attack escalates, penalty applied |

### Reward Function

| Event | Reward |
|-------|--------|
| Revealing new evidence (analyze_log / trace_user) | +0.20 |
| Correctly identifying the threat actor | +0.30 |
| Correct mitigation (block_ip / disable_account / restart_service) | +0.50 |
| Fast resolution (< 40% of max steps) | +0.20 bonus |
| Wrong action (wrong target) | −0.30 |
| Ignoring the attack (each step) | −0.20 |
| Full system compromise | −0.60 |

Final episode score is normalised to **0.0 – 1.0** and reported in `info["final_score"]`.

---

## 🧩 Tasks

### Task 1 — Brute Force Detection (Easy)
A brute-force attack is underway against the authentication service.
Multiple failed login attempts are visible immediately.
**Expected flow:** analyze logs → confirm repeated failures from one IP → block that IP.

- Max steps: 12
- Required actions: `block_ip("192.168.1.47")`
- Oracle score: ~0.97

### Task 2 — Suspicious Login / Account Takeover (Medium)
A legitimate-looking login occurred from a geographically impossible location.
The agent must distinguish a compromised account from legitimate users and act before data is exfiltrated.

- Max steps: 14
- Required actions: `trace_user("carol")` → `disable_account("carol")`
- Oracle score: ~0.97

### Task 3 — Multi-Stage APT Kill Chain (Hard)
A sophisticated attack chain: phishing → privilege escalation → lateral movement → data exfiltration.
The agent must connect events across multiple logs, identify the compromised account, block the C2 IP, disable the account, and recover affected services.

- Max steps: 18
- Required actions: `block_ip("198.51.100.23")` + `disable_account("eve")` + `restart_service("database")` + `restart_service("prod-01")`
- Oracle score: ~0.94

---

## 🚀 Setup & Usage

### Option A — Local development with Uvicorn

```bash
git clone https://huggingface.co/spaces/your-username/incident-response-env
cd incident-response-env

pip install -r requirements.txt

# Run Task 1
TASK_ID=1 uvicorn server.app:app --host 0.0.0.0 --port 8000 --reload
```

### Option B — Docker

```bash
# Build
docker build -t incident-response-env:latest .

# Run Task 1
docker run -d -p 8000:8000 -e TASK_ID=1 incident-response-env:latest

# Run Task 3 with custom scaling
docker run -d -p 8000:8000 \
    -e TASK_ID=3 \
    -e WORKERS=4 \
    -e MAX_CONCURRENT_ENVS=100 \
    incident-response-env:latest
```

### Option C — HF Spaces

```bash
# Already deployed — connect directly
pip install git+https://huggingface.co/spaces/your-username/incident-response-env
```

---

## 🐍 Python Usage

### Async (recommended)

```python
import asyncio
from client import IncidentResponseEnv
from models import IncidentAction

async def main():
    async with IncidentResponseEnv(base_url="http://localhost:8000") as env:
        # Task 1 — Brute Force
        obs = await env.reset(task_id=1)
        print(f"Logs: {[l.log_id for l in obs.logs]}")
        print(f"Alerts: {[a.message for a in obs.alerts]}")

        # Investigate
        result = await env.step(IncidentAction(action_type="analyze_log", target="L001"))
        print(f"reward={result.reward}  new_logs={[l.log_id for l in result.observation.logs]}")

        # Mitigate
        result = await env.step(IncidentAction(action_type="block_ip", target="192.168.1.47"))
        print(f"done={result.done}  score={result.info.get('final_score')}")

asyncio.run(main())
```

### Sync wrapper

```python
from client import IncidentResponseEnv
from models import IncidentAction

with IncidentResponseEnv(base_url="http://localhost:8000").sync() as env:
    obs = env.reset(task_id=2)
    result = env.step(IncidentAction(action_type="trace_user", target="carol"))
    result = env.step(IncidentAction(action_type="disable_account", target="carol"))
    print(f"Score: {result.info['final_score']}")
```

---

## 📊 Baseline

Run the LLM baseline against all tasks:

```bash
export OPENAI_API_KEY="sk-..."
export ENV_URL="http://localhost:8000"

python baseline.py
```

Expected output (gpt-4o-mini):

```
Task 1: mean_score=0.8700  success_rate=1.00
Task 2: mean_score=0.7600  success_rate=0.67
Task 3: mean_score=0.5200  success_rate=0.33
Overall mean score: 0.7167
```

Results are written to `baseline_results.json`.

---

## 📋 Graders

Run the oracle graders to verify environment correctness:

```bash
python graders.py --url http://localhost:8000
```

---

## 🌐 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ws` | WebSocket | Persistent session (recommended) |
| `/health` | GET | Health check |
| `/reset` | POST | Reset environment (stateless HTTP) |
| `/step` | POST | Execute action (stateless HTTP) |
| `/state` | GET | Full internal state |
| `/web` | GET | Interactive browser UI |
| `/docs` | GET | OpenAPI documentation |

---

## 🏗 Project Structure

```
incident_response_env/
├── models.py          # Typed Pydantic models (Action, Observation, State)
├── tasks.py           # 3 task scenario definitions
├── client.py          # Async + sync Python client
├── graders.py         # Programmatic graders (0.0–1.0)
├── baseline.py        # LLM baseline inference script
├── server/
│   ├── app.py         # FastAPI server (WebSocket + HTTP)
│   └── environment.py # Core environment logic (reset/step/state)
├── Dockerfile
├── openenv.yaml
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Why This Environment?

Most RL environments for LLMs test single-step classification. This environment tests:

- **Multi-step reasoning** — you can't block the right IP without first discovering it through logs
- **Evidence-based decision making** — wrong mitigation actions are penalised
- **Dynamic adversary** — the attack progresses if you're slow
- **Trajectory-level reward** — the entire sequence of decisions matters

These properties make it suitable for training and evaluating agents on realistic SOC workflows.
