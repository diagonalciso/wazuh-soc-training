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

Drills span a **mixed estate**: Linux/web hosts (SSH brute force, web attacks)
**and** Windows/Active-Directory hosts (RDP brute force, Kerberoasting, AS-REP
roasting, PowerShell cradles, LOLBins, LSASS dumping, ransomware precursors, C2
beaconing, lateral movement + log wiping). Windows hosts show a real **Windows OS
identity** in the dashboard, and Windows drills only land on Windows agents.

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

**Linux / web** scenarios use event templates confirmed to fire on a live manager
**and** to carry `data.srcip` (so the source shows up in triage and on an attack
map):

| Template | Fires rule | Bucket |
|----------|-----------|--------|
| `sshd_invalid` / `sshd_failed` | 5710 / 5716 (`authentication_failed`) | brute force |
| `web_sqli` / `web_xss` / `web_traversal` / `web_cmdinj` | 31106 (`web,accesslog,attack`, HTTP 200) | web attack |

**Windows / Sysmon** scenarios inject EventChannel JSON (Security + Sysmon) and
fire a bundled custom rule pack, `rules/training_rules.xml` (IDs **100100–100161**,
installed by `bootstrap.sh`):

| Injected event | Fires rule | Covers |
|----------------|-----------|--------|
| 4625 (+ type 10 / freq) | 100110–100112 | brute force, password spray, RDP brute |
| 4740 | 100113 | account lockout |
| 4769 RC4 / 4768 preauth-0 | 100120 / 100121 | Kerberoasting / AS-REP roasting |
| 4720 / 4728·4732 | 100130 / 100131 | rogue account + privileged-group add |
| 1102 / 4624 type 3 | 100133 / 100134 | log clearing / lateral movement |
| Sysmon 1 (command line) | 100141–100144 | encoded PowerShell, LOLBins, LSASS dump, shadow-copy delete |
| Sysmon 3 / 11 (freq) | 100151 / 100161 | C2 beaconing / ransomware mass-encryption |

> **Why a custom pack?** Stock Wazuh 60000-range Windows rules gate on an internal
> `windows_eventchannel` decoder that only a real agent's logcollector reaches.
> Queue-injected events decode via the generic `json` decoder, so the pack keys on
> `decoded_as json` + the same `win.*` fields and alerts identically.

Adding new templates: verify with `wazuh-logtest` that the rule fires (and, for
network attacks, that `srcip` is decoded) before wiring it into a scenario.

## Scenarios

24 drills across three levels; the tool serves a random one at the chosen level.
Titles are hidden from the trainee (shown only at debrief).

**Linux / web** (stock rules 5710/5716/31106):

| File | Level | Teaches |
|------|-------|---------|
| `scenarios/01-ssh-bruteforce.json` | beginner | source-IP + host identification, containment basics |
| `scenarios/04-distributed-ssh-bruteforce.json` | beginner | enumerating *all* sources (4+), not under-scoping the block list |
| `scenarios/02-web-app-attack.json` | intermediate | payload classification, reading HTTP 200 = success, web response |
| `scenarios/05-ssh-password-spray.json` | intermediate | spray vs brute force, T1110.003, MFA/lockout response |
| `scenarios/03-multistage-intrusion.json` | advanced | separating actors, kill-chain progression, prioritisation |
| `scenarios/06-web-rce-attempt.json` | advanced | command injection / RCE, 200 = possible compromise, IR response |

**Windows / Sysmon** (custom pack 100100–100161, Windows agents only):

| File | Level | Event(s) | Teaches |
|------|-------|----------|---------|
| `scenarios/07-win-rdp-bruteforce.json` | beginner | 4625 type 10 | RDP brute force, T1110.001 |
| `scenarios/08-win-account-lockout.json` | beginner | 4625 → 4740 | single-account guessing + lockout |
| `scenarios/09-win-password-spray-dc.json` | intermediate | 4625 (many users) | spray shape, hunt the one success, T1110.003 |
| `scenarios/10-win-kerberoasting.json` | intermediate | 4769 RC4 | Kerberoasting, RC4 tell, T1558.003 |
| `scenarios/11-win-powershell-cradle.json` | intermediate | Sysmon 1 | encoded PowerShell download cradle, T1059.001 |
| `scenarios/12-win-lolbin-exec.json` | intermediate | Sysmon 1 | LOLBin abuse, T1218 |
| `scenarios/13-win-rogue-admin.json` | intermediate | 4720 + 4732 | rogue privileged account, T1136.002 / T1098 |
| `scenarios/14-win-asrep-roasting.json` | advanced | 4768 preauth 0 | AS-REP roasting, T1558.004 |
| `scenarios/15-win-cred-dump-lsass.json` | advanced | Sysmon 1 | LSASS dump via comsvcs, T1003.001 |
| `scenarios/16-win-ransomware-preencryption.json` | advanced | Sysmon 1 + 11 | shadow-copy delete + mass rewrite, T1486 / T1490 |
| `scenarios/17-win-c2-beacon.json` | advanced | Sysmon 3 | periodic C2 beacon, T1071.001 |
| `scenarios/18-win-lateral-log-cleared.json` | advanced | 4624 type 3 + 1102 | lateral movement + log wipe, T1021 / T1070.001 |

**Linux assume-breach** (adversary already inside via stolen creds / valid
sessions — stock rules 5715/5402-5403/5902 + custom pack 100209–100215, Linux
agents only):

| File | Level | Event(s) | Teaches |
|------|-------|----------|---------|
| `scenarios/19-linux-stolen-cred-login.json` | intermediate | 5715 (Accepted password) | valid-account abuse vs brute force — a clean success with no failures, T1078 |
| `scenarios/20-linux-hands-on-keyboard.json` | advanced | 5715 → 5402/5403 → 100212 → 100211 | live operator: login → sudo → download → reverse shell, T1078/T1548/T1105/T1059.004 |
| `scenarios/21-linux-persistence-implant.json` | advanced | 5715 + 5902 + 100210 + 100215 | three footholds (rogue user, backdoor key, cron); why a password reset isn't enough, T1136/T1098.004/T1053.003 |
| `scenarios/22-linux-antiforensics.json` | advanced | 5715 + 100213 + 100214 | history + system-log wiping; local logs untrusted, pivot to forwarded copy, T1070.003/.002 |
| `scenarios/23-linux-lateral-session.json` | advanced | 5715 (internal srcip) + 5402/5403 | east-west movement with a reused key; internal RFC1918 source is the tell, T1021.004 |
| `scenarios/24-linux-full-breach.json` | advanced | full 5715→5402/5403→100210→100212→100211→100214 chain | capstone: credential access to anti-forensics; complete eviction plan, T1078→T1070.002 |

The post-exploitation on-host commands (reverse shell, log wipe, key implant,
cron) have no reliable stock rule, so they are injected as `snoopy` command-audit
lines and matched by the training pack on `full_log` — the command itself is the
evidence the analyst reads.

A scenario is one JSON file: `briefing`, `dashboard_hint`, `inject.steps`
(template + agent + srcips + count/pacing), `ground_truth`, `questions`
(types: `choice`, `multi`, `ipset`, `text`), and an optional `randomize` block.
Drop a new file in `scenarios/` and restart — no code change.

### Per-run randomisation

`randomizer.py` "materialises" a template into a concrete run at start:

```json
"randomize": {
    "ips":      {"SRC1": "bruteforce", "SRC2": "bruteforce"},
    "users":    {"USER1": true},
    "services": {"SVC1": true},
    "targets":  {"TARGET": {"question": "target", "os": "windows"}}
}
```

Referenced as `$TOKENS` anywhere in the scenario. `ips` draws distinct IPs from a
named pool; `users` / `services` draw account and SPN/service names (for
AD-flavoured Windows drills); `targets` draws distinct hosts from the live fleet
and rebuilds the named choice question's options (correct host + random decoys).
An optional `"os"` filter on a target (`windows` / `linux`) restricts the draw —
and its decoys — to that OS family, so a Windows drill only lands on a Windows
host and never offers a Linux decoy as an answer. Step `count` may be an
`[min, max]` range. Grading constants (attack class, MITRE id, severity) are
**not** randomised — they are the learning objective. The materialised run is
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
injector feeds their alerts. Each fleet line carries an **`os`** column
(`linux | windows-server | windows-10 | windows-11`) — the simulator reports it in
the keepalive so Windows hosts (dc01, ws01, fs01…) show a real **Windows OS** in
the dashboard, and `TRAIN_AGENTS` (`id:name:os`) tells the tool which drills each
host can run. A realistic mixed AD + Linux DMZ estate ships in
`lab/fleet.example.txt`. Full runbook + manual stages + the optional *real-agent
container* path: **[docs/DEPLOY.md](docs/DEPLOY.md)**.

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

## License

**[PolyForm Noncommercial License 1.0.0](LICENSE)** — © CisoDiagonal.

You may use, copy, modify, and share this software **for noncommercial purposes
only**. Personal, research, educational, government, and other nonprofit use is
permitted. **Commercial use is not permitted** — including selling the software,
selling access to it, using it in a paid product or service, or otherwise using it
for commercial advantage. For a commercial license, contact the author.
