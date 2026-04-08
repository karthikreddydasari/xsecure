"""
Task definitions for the Incident Response environment.
Each task defines a concrete scenario (easy → medium → hard)
with pre-seeded logs, alerts, hidden state, and success criteria.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class TaskScenario:
    task_id: int
    name: str
    description: str
    attack_type: str
    attacker_ip: str
    target_user: str
    target_service: str
    max_progress: int
    max_steps: int

    # Visible at reset
    initial_logs: List[Dict]
    initial_alerts: List[Dict]
    initial_services: List[Dict]
    initial_active_users: List[str]

    # Incremental logs revealed via analyze_log / trace_user
    hidden_logs: Dict[str, List[Dict]]   # keyed by trigger_action
    hidden_user_logs: Dict[str, List[Dict]]  # keyed by user_id

    # Correct targets the agent must identify
    correct_ips: List[str]
    correct_users: List[str]
    correct_services: List[str]

    # Stage info for multi-stage attacks
    stages: int = 1


# ---------------------------------------------------------------------------
# TASK 1 — Easy (Brute Force Attack)
# ---------------------------------------------------------------------------

TASK_1 = TaskScenario(
    task_id=1,
    name="Brute Force Detection",
    description=(
        "A brute-force attack is underway against the authentication service. "
        "Multiple failed login attempts are visible in the logs. "
        "Identify the attacker IP and block it before the admin account is compromised."
    ),
    attack_type="brute_force",
    attacker_ip="192.168.1.47",
    target_user="admin",
    target_service="auth-service",
    max_progress=3,
    max_steps=12,

    initial_logs=[
        {"log_id": "L001", "message": "Failed login for user 'admin' from 192.168.1.47", "timestamp": "09:01:02"},
        {"log_id": "L002", "message": "Failed login for user 'admin' from 192.168.1.47", "timestamp": "09:01:05"},
        {"log_id": "L003", "message": "Normal request from 10.0.0.5", "timestamp": "09:01:08"},
        {"log_id": "L004", "message": "Failed login for user 'admin' from 192.168.1.47", "timestamp": "09:01:11"},
    ],
    initial_alerts=[
        {"alert_id": "A001", "message": "Multiple failed logins detected for 'admin'", "severity": "high"},
    ],
    initial_services=[
        {"name": "auth-service",  "status": "running"},
        {"name": "web-server",    "status": "running"},
        {"name": "database",      "status": "running"},
    ],
    initial_active_users=["admin", "alice", "bob"],

    hidden_logs={
        "L001": [
            {"log_id": "L005", "message": "192.168.1.47 tried 120 passwords in last 60 seconds", "timestamp": "09:01:15"},
            {"log_id": "L006", "message": "Rate limit triggered for 192.168.1.47 (threshold exceeded)", "timestamp": "09:01:16"},
        ],
        "L002": [
            {"log_id": "L007", "message": "Automated tool signature detected: hydra/1.0 user-agent from 192.168.1.47", "timestamp": "09:01:17"},
        ],
    },
    hidden_user_logs={
        "admin": [
            {"log_id": "L008", "message": "Admin account has 0 successful logins in last 10 min (all blocked)", "timestamp": "09:01:20"},
        ],
    },

    correct_ips=["192.168.1.47"],
    correct_users=[],
    correct_services=[],
    stages=1,
)


# ---------------------------------------------------------------------------
# TASK 2 — Medium (Suspicious Login / Account Takeover)
# ---------------------------------------------------------------------------

TASK_2 = TaskScenario(
    task_id=2,
    name="Suspicious Login — Account Takeover",
    description=(
        "A legitimate-looking login has occurred from an unusual geographic location. "
        "Behavioral signals suggest account compromise. "
        "Investigate the user's activity and disable the account if you confirm anomalous behavior "
        "before data exfiltration occurs."
    ),
    attack_type="suspicious_login",
    attacker_ip="203.0.113.88",
    target_user="carol",
    target_service="file-server",
    max_progress=3,
    max_steps=14,

    initial_logs=[
        {"log_id": "L001", "message": "Successful login for 'carol' from 203.0.113.88 (Singapore)", "timestamp": "14:22:01"},
        {"log_id": "L002", "message": "carol accessed /finance/Q3_report.xlsx", "timestamp": "14:22:30"},
        {"log_id": "L003", "message": "Normal request from alice at 10.0.0.8", "timestamp": "14:22:35"},
        {"log_id": "L004", "message": "carol accessed /hr/salary_data.csv", "timestamp": "14:22:58"},
    ],
    initial_alerts=[
        {"alert_id": "A001", "message": "Login from new geolocation for 'carol' (usual: India, now: Singapore)", "severity": "medium"},
        {"alert_id": "A002", "message": "Unusual file access volume for 'carol'", "severity": "low"},
    ],
    initial_services=[
        {"name": "file-server",   "status": "running"},
        {"name": "auth-service",  "status": "running"},
        {"name": "web-server",    "status": "running"},
    ],
    initial_active_users=["carol", "alice", "bob", "dave"],

    hidden_logs={
        "L001": [
            {"log_id": "L005", "message": "carol's last login was 6 days ago from Hyderabad, India (10.5.1.2)", "timestamp": "14:23:00"},
            {"log_id": "L006", "message": "Geo-distance between sessions: 4,200 km — impossible travel in 2 h", "timestamp": "14:23:01"},
        ],
        "L002": [
            {"log_id": "L007", "message": "carol has downloaded 340 MB of files in 3 minutes (normal avg: 2 MB/session)", "timestamp": "14:23:10"},
            {"log_id": "L008", "message": "carol attempted bulk-download of /finance/* directory", "timestamp": "14:23:15"},
        ],
        "L004": [
            {"log_id": "L009", "message": "Exfil pattern detected: files zipped and queued to external SFTP 203.0.113.90", "timestamp": "14:23:20"},
        ],
    },
    hidden_user_logs={
        "carol": [
            {"log_id": "L010", "message": "carol's password was reset via phishing link 4 h ago — MFA bypassed", "timestamp": "14:23:25"},
            {"log_id": "L011", "message": "carol's account has API token generated from 203.0.113.88", "timestamp": "14:23:26"},
        ],
    },

    correct_ips=[],
    correct_users=["carol"],
    correct_services=[],
    stages=1,
)


# ---------------------------------------------------------------------------
# TASK 3 — Hard (Multi-Stage Attack: Phishing → Escalation → Exfiltration)
# ---------------------------------------------------------------------------

TASK_3 = TaskScenario(
    task_id=3,
    name="Multi-Stage Attack — APT Kill Chain",
    description=(
        "A sophisticated multi-stage attack is in progress: "
        "Stage 1: An attacker used phishing to steal credentials. "
        "Stage 2: The compromised account is performing privilege escalation. "
        "Stage 3: The attacker is moving laterally to access the database. "
        "You must analyze logs, connect the events, identify the compromised account, "
        "and take targeted actions to stop the attack chain before database exfiltration completes."
    ),
    attack_type="multi_stage",
    attacker_ip="198.51.100.23",
    target_user="eve",
    target_service="database",
    max_progress=4,
    max_steps=18,

    initial_logs=[
        {"log_id": "L001", "message": "eve clicked a link in email from 'it-support@company-secure.net'", "timestamp": "10:05:00"},
        {"log_id": "L002", "message": "Successful login for 'eve' from 198.51.100.23", "timestamp": "10:07:12"},
        {"log_id": "L003", "message": "Normal build pipeline run by ci-bot", "timestamp": "10:08:00"},
        {"log_id": "L004", "message": "eve modified /etc/sudoers on host prod-01", "timestamp": "10:09:44"},
        {"log_id": "L005", "message": "Database query spike: 2,400 queries/min from prod-01 (normal: 120)", "timestamp": "10:11:00"},
    ],
    initial_alerts=[
        {"alert_id": "A001", "message": "Phishing link clicked by 'eve' — domain flagged by threat intel", "severity": "high"},
        {"alert_id": "A002", "message": "Privilege escalation attempt detected on prod-01", "severity": "high"},
        {"alert_id": "A003", "message": "Abnormal database query rate from prod-01", "severity": "medium"},
    ],
    initial_services=[
        {"name": "auth-service",  "status": "running"},
        {"name": "web-server",    "status": "running"},
        {"name": "database",      "status": "degraded"},
        {"name": "prod-01",       "status": "running"},
    ],
    initial_active_users=["eve", "alice", "ci-bot", "frank", "grace"],

    hidden_logs={
        "L001": [
            {"log_id": "L006", "message": "Phishing page at company-secure.net harvested eve's credentials + session token", "timestamp": "10:05:30"},
            {"log_id": "L007", "message": "company-secure.net resolves to 198.51.100.23 (attacker-controlled)", "timestamp": "10:05:31"},
        ],
        "L002": [
            {"log_id": "L008", "message": "Session from 198.51.100.23 is using stolen token (different device fingerprint)", "timestamp": "10:07:15"},
            {"log_id": "L009", "message": "10 concurrent sessions opened from 198.51.100.23 within 30 s", "timestamp": "10:07:45"},
        ],
        "L004": [
            {"log_id": "L010", "message": "sudoers modification grants root to eve on ALL hosts — lateral movement risk", "timestamp": "10:09:50"},
            {"log_id": "L011", "message": "eve's sudo session on prod-01 installed reverse shell (python3 -c '...')", "timestamp": "10:10:00"},
        ],
        "L005": [
            {"log_id": "L012", "message": "Queries from prod-01 selecting PII columns: SSN, credit_card, email", "timestamp": "10:11:10"},
            {"log_id": "L013", "message": "Data staged at /tmp/.x/ — 1.2 GB; upload to 198.51.100.24 in progress", "timestamp": "10:11:20"},
        ],
    },
    hidden_user_logs={
        "eve": [
            {"log_id": "L014", "message": "eve's account created 3 backdoor API keys in last 5 minutes", "timestamp": "10:10:30"},
            {"log_id": "L015", "message": "eve added 198.51.100.23 to trusted-IPs whitelist (stealth persistence)", "timestamp": "10:10:35"},
        ],
        "ci-bot": [
            {"log_id": "L016", "message": "ci-bot credentials were NOT compromised — red herring", "timestamp": "10:08:10"},
        ],
    },

    correct_ips=["198.51.100.23"],
    correct_users=["eve"],
    correct_services=["database", "prod-01"],
    stages=3,
)


ALL_TASKS: Dict[int, TaskScenario] = {
    1: TASK_1,
    2: TASK_2,
    3: TASK_3,
}
