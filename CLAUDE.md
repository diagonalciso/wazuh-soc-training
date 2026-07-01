# CLAUDE.md — wazuh-soc-training

Standalone SOC analyst training platform for Wazuh. Injects labeled synthetic
attacks into a **live** Wazuh manager; analysts triage in the real dashboard;
the tool auto-grades their triage. Pure Python 3 stdlib, port 8101.

## Layout

| File | Role |
|------|------|
| `app.py` | stdlib `ThreadingHTTPServer` web UI (scenario picker, drill, questions, debrief, leaderboard) |
| `injector.py` | queue-socket injector + scenario runner (background thread, real-world pacing) |
| `scoring.py` | deterministic grading + SQLite progress (`attempts` table) |
| `config.py` | all config via env |
| `scenarios/*.json` | scenario definitions (data, no code) |
| `wazuh-soc-training.service` | systemd unit (runs as root for the queue socket) |
| `docs/ADMIN.md` | operator + scenario-authoring manual |

## Hard constraints

- **Runs ON the Wazuh manager.** `injector.py` writes to
  `/var/ossec/queue/sockets/queue` (local UNIX DGRAM socket, owned `wazuh:wazuh`).
  Cannot inject remotely — deploy to the manager (e.g. 10.10.0.10).
- **Only verified templates.** Every event template must fire a real rule AND
  decode `data.srcip`. Verified set: `sshd_invalid`/`sshd_failed` → 5710/5716
  (brute force); `web_sqli`/`web_xss`/`web_traversal`/`web_cmdinj` → 31106 (web
  attack, HTTP 200). Prove new templates in `wazuh-logtest` before adding.
- Wire message format: `1:[<id>] (<name>) any-><location>:<raw log>`.

## Run / test

```bash
# local UI smoke-test (injection will fail harmlessly without a real socket):
QUEUE_SOCKET=/tmp/x TRAIN_DB=/tmp/t.db TRAIN_PORT=8151 python3 app.py

# syntax + scenario validation
python3 -m py_compile app.py injector.py scoring.py config.py
python3 -c "import json,glob;[json.load(open(p)) for p in glob.glob('scenarios/*.json')]"
```

Grading verified: perfect answers = 100%, partial (half IPs + wrong choice +
wrong multi pick) = ~37.5% with penalties.

## Deploy target

10.10.0.10 (lab Wazuh 4.14.5). Agents there: 001 web01, 002 app01,
003 db01, 004 ws01. Trainee dashboard = `https://10.10.0.10`.

## Related

Injection technique shared with the standalone attack-map work (memory
`wazuh-inject-test-events`, `wazuh-attackmap-addon`).
