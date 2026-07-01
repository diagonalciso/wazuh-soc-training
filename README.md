# wazuh-soc-training

> ## ⚠️ TRAINING TOOL — not a security control
> Injects **synthetic, labeled** attack events into a **live Wazuh manager** so
> analysts can practise triage in the real dashboard. Run it on a lab/training
> Wazuh, never a production manager you rely on for real detection. No warranty.

A self-contained SOC analyst training platform for [Wazuh](https://wazuh.com). It
drives real drills end-to-end:

1. Trainee picks a **scenario** (SSH brute-force, web-app attack, multi-stage
   intrusion, …).
2. Starting the drill **injects a labeled attack** into the live Wazuh manager via
   the analysisd queue socket — real alerts appear in the **real Wazuh dashboard**.
3. Trainee **triages in the actual dashboard** (link provided), then answers the
   scenario's triage questions.
4. Answers are **auto-graded** against ground truth, with a per-question debrief,
   score, and a **leaderboard** (SQLite).

Because the alerts are real Wazuh alerts, everything the analyst learns —
Discover queries, `rule.groups`, `data.srcip` pivots, agent correlation — is
transferable to the job.

Pure Python 3 **stdlib**. No pip, no Node, no external services.

## How it works

```
 scenario JSON (labeled attack + ground truth + questions)
        │
        ▼
 injector.py ──► analysisd queue socket ──► Wazuh rules ──► wazuh-alerts-*
        │                                                        │
        │                                              real Wazuh dashboard
        ▼                                                        │
 app.py (web UI)  briefing + questions ◄── trainee triages ──────┘
        │
        ▼
 scoring.py  grade vs ground_truth ──► debrief + leaderboard (SQLite)
```

The injector **must run on the Wazuh manager** — the queue socket
(`/var/ossec/queue/sockets/queue`) is a local UNIX socket owned `wazuh:wazuh`.

## Verified rule coverage

Scenarios only use event templates confirmed to fire on a live manager **and**
to carry `data.srcip` (so the source shows up in triage and on an attack map):

| Template | Fires rule | Bucket |
|----------|-----------|--------|
| `sshd_invalid` / `sshd_failed` | 5710 / 5716 (`authentication_failed`) | brute force |
| `web_sqli` / `web_xss` / `web_traversal` / `web_cmdinj` | 31106 (`web,accesslog,attack`, HTTP 200) | web attack |

Adding new templates: verify with `wazuh-logtest` that the rule fires and
`srcip` is decoded before wiring it into a scenario.

## Scenarios

| File | Level | Teaches |
|------|-------|---------|
| `scenarios/01-ssh-bruteforce.json` | beginner | source-IP + host identification, containment basics |
| `scenarios/02-web-app-attack.json` | intermediate | payload classification, reading HTTP 200 = success, web response |
| `scenarios/03-multistage-intrusion.json` | advanced | separating actors, kill-chain progression, prioritisation |

A scenario is one JSON file: `briefing`, `dashboard_hint`, `inject.steps`
(template + agent + srcips + count + pacing), `ground_truth`, and `questions`
(types: `choice`, `multi`, `ipset`, `text`). Drop a new file in `scenarios/` and
restart — no code change.

## Run

```bash
cp wazuh-soc-training.env.example /etc/wazuh-soc-training.env   # edit it
sudo env $(grep -v '^#' /etc/wazuh-soc-training.env | xargs) python3 app.py
# http://<manager>:8101/
```

Needs write access to the queue socket → run as `root` or the `wazuh` user. See
[docs/ADMIN.md](docs/ADMIN.md) for operations.

## Full lab from scratch

The **only real thing you install by hand is one Wazuh all-in-one server**. The
rest — a fleet of endpoints, their agents, the network, and the attacks — is
scripted. See **[docs/DEPLOY.md](docs/DEPLOY.md)** for the end-to-end runbook.

```bash
# 1. install the real Wazuh AIO server (VM / bare metal) — see DEPLOY.md stage 1
# 2. stand up virtual endpoints (Wazuh agents in containers) that enroll to it:
cd lab
cp lab.env.example lab.env        # MANAGER_IP, ENROLL_PASSWORD, WAZUH_VERSION
cp fleet.example.txt fleet.txt    # web01/db01/dc01/ws01... names, ips, roles
./deploy-lab.sh                   # builds agent image + starts the fleet
# 3. install this tool on the manager, wire TRAIN_AGENTS to the real agent ids:
cd .. && ./deploy.sh <user>@<server-ip>
lab/agents-to-trainenv.sh <user>@<server-ip>   # prints TRAIN_AGENTS=001:web01,...
```

`lab/` contents: `agent.Dockerfile` + `entrypoint.sh` (a virtual endpoint),
`deploy-lab.sh` / `teardown-lab.sh` (fleet up/down), `agents-to-trainenv.sh`
(map real agent ids into the tool's env).

## Routes

| Route | Description |
|-------|-------------|
| `/` | scenario picker + leaderboard |
| `/scenario?id=&trainee=` | **launches the drill** (injects) + briefing + questions |
| `/submit` | grade answers → debrief |
| `/run?id=` | injection progress (JSON) |
| `/api/scenarios` | scenario ids (JSON) |
| `/healthz` | `{"ok":true}` |

## Security / caveats

- It **injects events into Wazuh**. Use a lab/training manager. Test alerts are
  clearly labeled attacks against real agent names configured in the env.
- No page auth by default (lab tool). Bind to an internal interface / front with a
  reverse proxy if needed. Security headers (CSP, nosniff, frame-options,
  no-referrer) are set on every response.
- Read-only toward the indexer; injection is the only write path, and only into
  the alert pipeline.

Status: proof-of-concept, provided as-is.
