# Real-World Deployment — from bare metal to a running SOC drill

The **only real thing you provision by hand is one Wazuh all-in-one server**
(VM or bare metal). Everything else — a fleet of endpoints, their agents, the
lab network, and the attacks — is stood up by the scripts in this repo.

```
  YOU install:            [ Wazuh all-in-one server ]   (VM / bare metal, real)
                                     ^        ^
  deploy-lab.sh spins:   virtual endpoints   |          (Docker: web01, db01, dc01, ws01 ...)
  (agents enroll) ------------┘               |
  deploy.sh installs:                 wazuh-soc-training  (drill launcher, on the manager)
                                              |
  a trainee:  picks a scenario -> injector fires labeled attacks ->
              real alerts land in the real dashboard -> they triage -> auto-graded
```

---

## Stage 0 — sizing

| Component | Min | Comfortable |
|-----------|-----|-------------|
| Wazuh AIO server | 4 vCPU / 8 GB / 50 GB | 8 vCPU / 16 GB / 100 GB SSD |
| Docker host for endpoints (can be the same box) | 2 vCPU / 4 GB | 4 vCPU / 8 GB |

OS: any systemd Linux Wazuh supports (Ubuntu 22.04 / RHEL 9 / Debian 12).
Endpoints run as containers so 8 of them cost ~1–2 GB total.

---

## Stage 1 — install the real Wazuh server (all-in-one)

On the server VM / metal, as root:

```bash
# kernel tunable OpenSearch needs (persist it too)
sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-wazuh.conf

# official all-in-one installer (indexer + manager + dashboard on one host)
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
bash ./wazuh-install.sh -a -i

# grab the generated admin password
tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | \
  grep -A1 "username: 'admin'"
```

Verify:

```bash
curl -sk -u admin:<PASSWORD> https://127.0.0.1:9200/_cluster/health | grep -o '"status":"[a-z]*"'
# -> "status":"green" (yellow is OK on a single node)
```

Open the dashboard at `https://<server-ip>/` (login `admin`). This is where
trainees will triage. Note the URL — it becomes `WAZUH_DASHBOARD_URL` later.

### Firewall

Open from the Docker host to the server:

| Port | Purpose |
|------|---------|
| 1515/tcp | agent enrollment (authd) |
| 1514/tcp | agent events |
| 443/tcp | dashboard (analysts) |

```bash
firewall-cmd --add-port=1514/tcp --add-port=1515/tcp --add-port=443/tcp --permanent
firewall-cmd --reload      # (or ufw allow ...)
```

### (recommended) enrollment password

```bash
# on the server
echo "$(openssl rand -hex 16)" > /var/ossec/etc/authd.pass
chmod 640 /var/ossec/etc/authd.pass && chown root:wazuh /var/ossec/etc/authd.pass
systemctl restart wazuh-manager
```

Put that value in `lab/lab.env` as `ENROLL_PASSWORD`.

---

## Stage 2 — deploy the virtual endpoint fleet

On the Docker host (needs network reach to the server on 1514/1515):

```bash
cd lab
cp lab.env.example lab.env          # set MANAGER_IP, ENROLL_PASSWORD, WAZUH_VERSION
cp fleet.example.txt fleet.txt      # edit the fleet (names/ips/roles)
./deploy-lab.sh                     # builds the agent image, starts the fleet
```

`WAZUH_VERSION` **must be <= the server version** (agent never newer than
manager). Match it exactly for a clean lab (e.g. `4.14.5`).

Wait ~30–60 s, then confirm on the server:

```bash
/var/ossec/bin/agent_control -l         # fleet should read "Active"
```

or Dashboard → **Agents** → the fleet appears with hostnames + OS. Now you have
a realistic estate (web/app/db/dc/workstations) reporting to a real manager.

---

## Stage 3 — install the drill platform on the manager

The injector writes to the **local** analysisd queue socket, so
`wazuh-soc-training` runs **on the Wazuh server**. From this repo, on your
workstation:

```bash
./deploy.sh <user>@<server-ip>          # scp + install to /opt + systemd unit
```

Then on the server, wire the env to reality:

```bash
sudoedit /etc/wazuh-soc-training.env
#   WAZUH_DASHBOARD_URL=https://<server-ip>
#   TRAIN_AGENTS=<from the helper below>

# generate TRAIN_AGENTS from the real agent ids the manager assigned:
lab/agents-to-trainenv.sh <user>@<server-ip>     # prints TRAIN_AGENTS=001:web01,...

sudo systemctl enable --now wazuh-soc-training
curl -s http://127.0.0.1:8101/healthz            # {"ok":true}
```

---

## Stage 4 — run a drill

1. Trainee opens `http://<server-ip>:8101/`, enters a name, picks a scenario.
2. "Start drill" injects the labeled attack into the live manager (real-world
   pacing). Alerts appear in the **real** dashboard within seconds.
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
cd lab
./teardown-lab.sh                                  # remove endpoints + network
./teardown-lab.sh --purge-manager <user>@<server>  # also deregister the agents
```

---

## Notes & gotchas

- **Agent > manager version** breaks enrollment. Keep `WAZUH_VERSION` <= server.
- Injected events are stamped **now** by analysisd, so they show as live.
- Only the **verified** attack templates (`sshd_*`, `web_*`) both fire a rule
  and decode `srcip` on the stock ruleset. To add recon/DoS/malware scenarios
  you must add IDS/scan rules to the manager and prove them in `wazuh-logtest`
  first (see `docs/ADMIN.md`).
- Containers `--restart unless-stopped`, so the fleet survives a Docker-host
  reboot and re-reports automatically.
