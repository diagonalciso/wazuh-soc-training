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
# override with TRAIN_AGENTS="id:name,id:name,..."
_default_agents = "001:web01,003:db01,002:app01,004:ws01"
AGENTS = {}
for pair in os.getenv("TRAIN_AGENTS", _default_agents).split(","):
    if ":" in pair:
        _id, _name = pair.split(":", 1)
        AGENTS[_name.strip()] = _id.strip()
