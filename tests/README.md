# tests

Two self-tests that exercise the full drill loop against a **live lab**
(a running Wazuh manager + the training tool). Neither is a unit test; both
inject real events into the manager queue socket, so run them on the lab box.

## `http_suite.py` — end-to-end via HTTP
Drives every scenario through the running tool's HTTP endpoints and asserts a
perfect score:

```bash
# tool must be running (default http://127.0.0.1:8101)
python3 tests/http_suite.py
# WSOC_URL=http://host:8101 python3 tests/http_suite.py   # remote tool
```

For each scenario it does `GET /scenario` (server materialises + injects,
returns a `run_id`), a blank `POST /submit` to read the per-run correct key off
the debrief page, then a real `POST /submit` with those answers -> expects
`100.0%`. Leaves two `attempts` rows per scenario under trainee `http-suite`;
purge them if you want a clean leaderboard:

```sql
DELETE FROM attempts WHERE trainee IN ('http-suite');
```

## `drill_selftest.py` — module level
Materialises + fast-injects every scenario (no HTTP), then grades the
materialised key with correct answers (expect 100%) and one wrong choice
(expect a penalty), recording to the live `training.db`. Run as root with the
service env sourced:

```bash
sudo bash -c 'set -a; . /etc/wazuh-soc-training.env; set +a; \
  WSOC_INSTALL=/opt/wazuh-soc-training python3 tests/drill_selftest.py'
```

Also reports the drawn target host + its OS family per run, so it catches
scenarios that land on the wrong OS (e.g. a Linux SSH drill targeting a
Windows host).
