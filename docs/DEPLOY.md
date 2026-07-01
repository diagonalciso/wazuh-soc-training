# Real-World Deployment — from bare metal to a running SOC drill

The **only real thing you provision is one Wazuh all-in-one server** (VM or bare
metal). Everything else — the fleet of endpoints, their agents, and the attacks
— is stood up by the scripts in this repo. Endpoints/agents are **DB-only**:
they exist only as registrations in the manager and are kept **Active** by a
keepalive simulator. No containers, no VMs per endpoint, no nested virtualization.

```
  YOU provide:      [ one Linux box / VM ]
                            |
  bootstrap.sh:     installs Wazuh AIO  +  enrolls DB-only fleet  +  runs the
                    keepalive simulator (agents show ACTIVE)  +  installs the tool
                            |
  a trainee:  picks a scenario -> injector fires labeled attacks (queue socket)
              -> real alerts land in the real dashboard -> triage -> auto-graded
```

Why this works: a Wazuh "agent" is three separable layers — **registration**
(pure DB, via authd), **alerts** (injected via the analysisd queue socket, tagged
to any agent), and **connection status** (keepalives on 1514). The simulator
sends valid encrypted keepalives so registered agents report Active. Only agent
**inventory** (syscollector/FIM) stays empty — irrelevant for alert-triage drills.

---

## Fast path — one command

You need: a fresh Linux box (Ubuntu 22.04 / Debian 12 / RHEL 9), root, internet.

```bash
git clone https://github.com/diagonalciso/wazuh-soc-training
cd wazuh-soc-training
sudo ./bootstrap.sh
```

`bootstrap.sh` installs Wazuh AIO (if absent), enrolls the fleet in
`lab/fleet.txt` (falls back to `fleet.example.txt`), starts the simulator, and
installs + starts the training tool. When it finishes it prints the dashboard
URL, the training URL, and the fleet agent list. Done.

Flags: `--no-wazuh` (Wazuh already installed), `SKIP_FLEET=1` (server + tool
only, no fake agents), `WAZUH_VERSION=4.14` (installer channel).

### …or as a throwaway VM (Vagrant)

If you'd rather not touch a real host, the repo ships a `Vagrantfile` that boots
an Ubuntu VM and runs the same `bootstrap.sh` inside it:

```bash
vagrant up                     # libvirt/KVM or VirtualBox; >=4GB RAM (LAB_MEM_MB=6144 default)
# dashboard  https://192.168.56.20
# training   http://192.168.56.20:8101
```

This is a **normal** VM (not nested), so it runs anywhere a hypervisor does.

---

## Stage 0 — sizing

| Component | Min | Comfortable |
|-----------|-----|-------------|
| Wazuh AIO server | 4 vCPU / 8 GB / 50 GB | 8 vCPU / 16 GB / 100 GB SSD |

That's the whole footprint — the DB-only fleet and the simulator cost a few MB.
OS: any systemd Linux Wazuh supports (Ubuntu 22.04 / RHEL 9 / Debian 12).

---

## What bootstrap.sh does (manual equivalent)

If you want to run the stages by hand (or understand the script):

### 1. install the real Wazuh server

```bash
sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-wazuh.conf
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
bash ./wazuh-install.sh -a -i
tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A1 "username: 'admin'"
```

Dashboard: `https://<server-ip>/` (login `admin`) — where trainees triage.

### 2. enroll the DB-only fleet

```bash
cd lab
cp fleet.example.txt fleet.txt        # edit names/ips/roles/groups
cat > lab.env <<EOF
MANAGER_IP=127.0.0.1
AUTH_PORT=1515
FLEET_FILE=fleet.txt
KEYS_OUT=$PWD/agent_sim.keys
EOF
./enroll-fleet.sh                     # authd enrollment -> writes agent_sim.keys + prints TRAIN_AGENTS
```

If the manager uses an enrollment password, add `AUTHD_PASS=...` to `lab.env`.

### 3. keep them Active (simulator)

```bash
# quick foreground test:
python3 agent_sim.py --manager 127.0.0.1 --keys agent_sim.keys --interval 15
# or as a service (bootstrap installs this):
sudo systemctl enable --now wazuh-agent-sim
/var/ossec/bin/agent_control -l       # fleet reads "Active" within ~1 min
```

### 4. install the drill tool (runs on the manager for the queue socket)

```bash
sudo install -d /opt/wazuh-soc-training && sudo cp -r . /opt/wazuh-soc-training/
sudo tee /etc/wazuh-soc-training.env >/dev/null <<EOF
QUEUE_SOCKET=/var/ossec/queue/sockets/queue
WAZUH_DASHBOARD_URL=https://<server-ip>
TRAIN_PORT=8101
TRAIN_BIND=0.0.0.0
TRAIN_DB=/opt/wazuh-soc-training/training.db
TRAIN_AGENTS=<from enroll-fleet.sh>
EOF
sudo chmod 600 /etc/wazuh-soc-training.env
sudo systemctl enable --now wazuh-soc-training
curl -s http://127.0.0.1:8101/healthz   # {"ok":true}
```

---

## Stage 4 — run a drill

1. Trainee opens `http://<server-ip>:8101/`, enters a name, picks a scenario.
2. "Start drill" injects the labeled attack into the live manager (real-world
   pacing). Alerts appear in the **real** dashboard within seconds, attributed to
   the (Active) fleet agents.
3. Trainee triages in the dashboard (widen time range to *last 30 min* if
   needed), then answers the triage questions in the tool.
4. Auto-graded vs ground truth → debrief + leaderboard.

Confirm an injection landed:

```bash
curl -sk -u admin:<PASS> "https://127.0.0.1:9200/wazuh-alerts-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"range":{"timestamp":{"gte":"now-10m"}}},
       "aggs":{"r":{"terms":{"field":"rule.id"}}}}' | python3 -m json.tool
```

---

## Teardown

```bash
sudo systemctl disable --now wazuh-agent-sim wazuh-soc-training
# deregister the fake agents on the manager:
for id in $(/var/ossec/bin/agent_control -ln | awk '{print $1}'); do
  /var/ossec/bin/manage_agents -r "$id"    # or use the Dashboard -> Agents
done
```

---

## Notes & gotchas

- **Agent > manager version** is irrelevant here — the simulator has no version
  gate — but enrolled IPs are cosmetic in DB-only mode.
- Injected events are stamped **now** by analysisd, so they show as live.
- DB-only agents show **Active** (keepalive) but have **empty inventory**
  (no syscollector/FIM). Fine for alert-triage drills; if you need real
  inventory panels, use the optional container path below.
- Only the **verified** attack templates (`sshd_*`, `web_*`) both fire a rule and
  decode `srcip` on the stock ruleset. To add recon/DoS/malware scenarios you must
  add IDS/scan rules and prove them in `wazuh-logtest` first (see `docs/ADMIN.md`).
- `manage_agents -a` is blocked while authd runs — enroll over :1515 (what
  `enroll-fleet.sh` does), don't add keys by hand.

---

## Optional — real agents instead of DB-only (containers)

If you want agents that are genuinely connected *with* inventory/FIM, the repo
also ships a container path: each endpoint is a real `wazuh-agent` in a
container that enrolls to the manager.

```bash
cd lab
cp lab.env.example lab.env            # MANAGER_IP, ENROLL_PASSWORD, WAZUH_VERSION
cp fleet.example.txt fleet.txt
./deploy-lab.sh                       # builds agent image, starts the fleet
./teardown-lab.sh --purge-manager <user>@<server>   # tear down + deregister
```

Heavier (needs Docker + `WAZUH_VERSION` <= manager), but the agents are real.
The DB-only path above is the recommended default for triage training.
```
