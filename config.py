"""Central config — all via environment (see wazuh-soc-training.env.example).

Nothing sensitive is hardcoded. Defaults target a Wazuh manager running on the
same host (analysisd queue socket is local; the injector MUST run on the manager).
"""
import os

# --- injection (analysisd queue socket, local to the Wazuh manager) ---
QUEUE_SOCKET = os.getenv("QUEUE_SOCKET", "/var/ossec/queue/sockets/queue")

# --- indexer (read-only, to score / verify events landed) ---
INDEXER_URL = os.getenv("INDEXER_URL", "https://127.0.0.1:9200")
INDEXER_USER = os.getenv("INDEXER_USER", "monitor")
INDEXER_PASS = os.getenv("INDEXER_PASS", "")
INDEXER_CA = os.getenv("INDEXER_CA", "")  # set = verify TLS; empty = verify off (localhost)

# --- trainee-facing real Wazuh dashboard (link target only) ---
DASHBOARD_URL = os.getenv("WAZUH_DASHBOARD_URL", "https://127.0.0.1")

# --- web app ---
PORT = int(os.getenv("TRAIN_PORT", "8101"))
BIND = os.getenv("TRAIN_BIND", "0.0.0.0")
DB_PATH = os.getenv("TRAIN_DB", os.path.join(os.path.dirname(__file__), "training.db"))

# --- content ---
SCENARIO_DIR = os.getenv("SCENARIO_DIR", os.path.join(os.path.dirname(__file__), "scenarios"))

# real agents on the target manager (name shown to trainee; id used in queue msg).
# override with TRAIN_AGENTS="id:name:os,id:name:os,..." — the os field is
# optional (default "linux") and lets scenarios target host-appropriate attacks
# (e.g. Kerberoasting only on a windows-server host). enroll-fleet.sh emits it.
#   os values: linux | windows-server | windows-10 | windows-11
_default_agents = ("001:web01:linux,002:app01:linux,003:db01:linux,"
                   "004:dc01:windows-server,005:ws01:windows-10")
AGENTS = {}       # name -> agent id
AGENT_OS = {}     # name -> os family ("linux" / "windows-*")
for pair in os.getenv("TRAIN_AGENTS", _default_agents).split(","):
    parts = [p.strip() for p in pair.split(":")]
    if len(parts) >= 2 and parts[0] and parts[1]:
        _id, _name = parts[0], parts[1]
        AGENTS[_name] = _id
        AGENT_OS[_name] = parts[2] if len(parts) >= 3 and parts[2] else "linux"
