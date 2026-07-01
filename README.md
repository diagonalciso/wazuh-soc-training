# wazuh-soc-training

> ## ⚠️ TRAINING TOOL — not a security control
> Injects **synthetic, labeled** attack events into a **live Wazuh manager** so
> analysts can practise triage in the real dashboard. Run it on a lab/training
> Wazuh, never a production manager you rely on for real detection. No warranty.

A self-contained SOC analyst training platform for [Wazuh](https://wazuh.com). It
drives real drills end-to-end:

1. Trainee picks a **difficulty level** (beginner / intermediate / advanced). They
   get a **random, unlabelled incident** at that level — the attack type is *not*
   revealed up front, so they have to classify it themselves (blind triage).
2. Starting the drill **injects a labeled attack** into the live Wazuh manager via
   the analysisd queue socket — real alerts appear in the **real Wazuh dashboard**.
   Every run is **randomised**: fresh source IPs, target host and event volumes are
   drawn each time, so the answer key changes on every start (no memorising).
3. Trainee **triages in the actual dashboard** (link provided), then answers the
   incident's triage questions.
4. Answers are **auto-graded** against that run's ground truth, with a per-question
   debrief (the attack is revealed here), score, and a **leaderboard** (SQLite).

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

Two drills per level; the tool serves a random one at the chosen level.

| File | Level | Teaches |
|------|-------|---------|
| `scenarios/01-ssh-bruteforce.json` | beginner | source-IP + host identification, containment basics |
| `scenarios/04-distributed-ssh-bruteforce.json` | beginner | enumerating *all* sources (4+), not under-scoping the block list |
| `scenarios/02-web-app-attack.json` | intermediate | payload classification, reading HTTP 200 = success, web response |
| `scenarios/05-ssh-password-spray.json` | intermediate | spray vs brute force, T1110.003, MFA/lockout response |
| `scenarios/03-multistage-intrusion.json` | advanced | separating actors, kill-chain progression, prioritisation |
| `scenarios/06-web-rce-attempt.json` | advanced | command injection / RCE, 200 = possible compromise, IR response |

A scenario is one JSON file: `briefing`, `dashboard_hint`, `inject.steps`
(template + agent + srcips + count/pacing), `ground_truth`, `questions`
(types: `choice`, `multi`, `ipset`, `text`), and an optional `randomize` block.
Drop a new file in `scenarios/` and restart — no code change.

### Per-run randomisation

`randomizer.py` "materialises" a template into a concrete run at start:

```json
"randomize": {
    "ips":     {"SRC1": "bruteforce", "SRC2": "bruteforce"},
    "targets": {"TARGET": {"question": "target"}}
}
```

Referenced as `$TOKENS` anywhere in the scenario. `ips` draws distinct IPs from a
named pool; `targets` draws distinct hosts from the live fleet and rebuilds the
named choice question's options (correct host + random decoys). Step `count` may
be an `[min, max]` range. Grading constants (attack class, MITRE id, severity)
are **not** randomised — they are the learning objective. The materialised run is
stored per `run_id` so grading uses the exact key that was injected.

## Run

```bash
cp wazuh-soc-training.env.example /etc/wazuh-soc-training.env   # edit it
sudo env $(grep -v '^#' /etc/wazuh-soc-training.env | xargs) python3 app.py
# http://<manager>:8101/
```

Needs write access to the queue socket → run as `root` or the `wazuh` user. See
[docs/ADMIN.md](docs/ADMIN.md) for operations.

## Full lab from scratch — one command

The **only real thing you provide is one Linux box**. Endpoints and agents are
**DB-only** — registered in the manager and kept **Active** by a keepalive
simulator (no containers, no VMs per endpoint, no nested virt).

```bash
git clone https://github.com/diagonalciso/wazuh-soc-training
cd wazuh-soc-training
sudo ./bootstrap.sh          # installs Wazuh AIO + enrolls fleet + simulator + tool
```

It prints the dashboard URL, the training URL, and the fleet when done. Prefer a
throwaway VM? `vagrant up` boots one and runs the same bootstrap inside it.

How the DB-only fleet works: `lab/enroll-fleet.sh` registers each agent via authd
(:1515); `lab/agent_sim.py` speaks Wazuh's encrypted 1514 protocol to send
keepalives so they show **Active** with no real endpoint; the queue-socket
injector feeds their alerts. Full runbook + manual stages + the optional
*real-agent container* path: **[docs/DEPLOY.md](docs/DEPLOY.md)**.

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
