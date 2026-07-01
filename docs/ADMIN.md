# Admin / Operator Manual — wazuh-soc-training

> ## ⚠️ TRAINING TOOL
> Injects labeled synthetic attacks into a **live** Wazuh manager. Lab/training
> managers only. Not a security control; no warranty.

## What it does

`app.py` serves a web UI on `TRAIN_PORT`. When a trainee starts a drill,
`injector.py` writes the scenario's labeled attack events to the local analysisd
queue socket. Wazuh decodes + rules them like any real log, so they land in
`wazuh-alerts-*` and show in the real dashboard. The trainee triages there, then
answers questions the tool grades against the scenario's ground truth.

Everything runs **on the Wazuh manager** — the queue socket is a local UNIX
socket owned `wazuh:wazuh`, so the service runs as `root` (or `wazuh`).

## Install

```bash
sudo mkdir -p /opt/wazuh-soc-training
sudo cp -r app.py injector.py scoring.py config.py scenarios /opt/wazuh-soc-training/
sudo cp wazuh-soc-training.env.example /etc/wazuh-soc-training.env
sudo chmod 600 /etc/wazuh-soc-training.env       # edit: dashboard URL, agents, port
sudo cp wazuh-soc-training.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-soc-training
curl -s http://127.0.0.1:8101/healthz
```

## Configuration (env)

| Var | Default | Meaning |
|-----|---------|---------|
| `QUEUE_SOCKET` | `/var/ossec/queue/sockets/queue` | analysisd injection socket (local) |
| `WAZUH_DASHBOARD_URL` | `https://127.0.0.1` | link the trainee opens to triage |
| `TRAIN_PORT` / `TRAIN_BIND` | `8101` / `0.0.0.0` | web listener |
| `TRAIN_DB` | `./training.db` | SQLite progress store |
| `TRAIN_AGENTS` | `001:web01,003:db01,002:app01,004:ws01` | `id:name` map; names shown to trainees, ids used in the queue message. Disconnected agents inject fine (analysisd only parses the location string). |
| `INDEXER_*` | — | reserved for a future "verify events landed" check |

Restart after edits: `sudo systemctl restart wazuh-soc-training`.

## Authoring scenarios

One JSON file in `scenarios/`. Shape:

```json
{
  "id": "my-scenario", "title": "...", "difficulty": "beginner",
  "briefing": "what the analyst is told",
  "dashboard_hint": "where to look in Wazuh",
  "inject": { "steps": [
     {"template": "sshd_invalid", "agent": "web01",
      "srcips": ["1.2.3.4"], "count": 8, "spacing": [0.5, 1.8]}
  ]},
  "ground_truth": { "attack_type": "...", "target": "..." },
  "questions": [
     {"id":"srcips","type":"ipset","weight":2,"prompt":"...","answer":["1.2.3.4"],"explain":"..."},
     {"id":"type","type":"choice","weight":1,"prompt":"...","options":["A","B"],"answer":"A","explain":"..."}
  ]
}
```

Templates available (all set `data.srcip`, all verified to fire):
`sshd_invalid`, `sshd_failed`, `web_sqli`, `web_xss`, `web_traversal`,
`web_cmdinj`. `spacing` is `[min,max]` seconds between events (real-world pace).

Question types + grading:

| Type | Input | Grading |
|------|-------|---------|
| `choice` | radio | exact match |
| `multi` | checkboxes | `(correct∩given − wrong picks)/correct`, floored at 0 |
| `ipset` | text (comma/space) | order-free IP set, partial credit, penalize extras |
| `text` | text | token/substring match vs accepted answers (list ok) |

**Adding a new template** (code change in `injector.py`): first prove it in
`wazuh-logtest` that (a) a rule fires and (b) `srcip` is decoded, e.g.

```bash
printf '<log line>\n' | sudo /var/ossec/bin/wazuh-logtest
```

Then add a branch in `injector._line()` and reference it from a scenario.

## Operations

```bash
systemctl status wazuh-soc-training --no-pager
journalctl -u wazuh-soc-training -f
curl -s http://127.0.0.1:8101/healthz
sqlite3 /opt/wazuh-soc-training/training.db "SELECT trainee,scenario,pct FROM attempts ORDER BY ts DESC LIMIT 10"
```

## Notes / limitations

- Injected events carry the **current** timestamp (analysisd stamps them on
  receipt), so they appear live in the dashboard. Widen the dashboard time range
  to "last 30 minutes" if you don't see them immediately (indexing lag ~seconds).
- Run state (injection progress) is in memory; a restart forgets in-flight drills
  but completed attempts persist in SQLite.
- No page auth by default (lab tool). Bind internal / reverse-proxy if needed.
