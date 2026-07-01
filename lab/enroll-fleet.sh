#!/usr/bin/env bash
# Enroll a fleet of DB-only agents into a real Wazuh manager via authd (:1515).
# No endpoints are created -- each agent is just a registration in the manager
# DB. agent_sim.py then keepalives them so they show Active.
#
#   ./enroll-fleet.sh                 # enroll everything in $FLEET_FILE
#   MANAGER_IP=10.0.0.5 ./enroll-fleet.sh
#
# Output: a client.keys-format file ($KEYS_OUT) for agent_sim.py --keys,
# and a TRAIN_AGENTS=... line for the training tool's env.
set -euo pipefail
cd "$(dirname "$0")"
if [ -f lab.env ]; then
  set -a
  # shellcheck source=/dev/null
  . ./lab.env
  set +a
fi

MANAGER_IP="${MANAGER_IP:-127.0.0.1}"
AUTH_PORT="${AUTH_PORT:-1515}"
FLEET_FILE="${FLEET_FILE:-fleet.txt}"
KEYS_OUT="${KEYS_OUT:-agent_sim.keys}"
AUTHD_PASS="${AUTHD_PASS:-}"        # set only if manager uses authd password

command -v openssl >/dev/null || { echo "openssl required" >&2; exit 1; }
[ -f "$FLEET_FILE" ] || { echo "fleet file '$FLEET_FILE' not found (copy fleet.example.txt)" >&2; exit 1; }

: > "$KEYS_OUT"
train_agents=""

enroll() {
  # $1 name  $2 ip  $3 group
  local name="$1" ip="$2" group="$3" req resp
  if [ -n "$AUTHD_PASS" ]; then
    req="OSSEC PASS: '${AUTHD_PASS}' OSSEC A:'${name}' G:'${group}' IP:'${ip}'"
  else
    req="OSSEC A:'${name}' G:'${group}' IP:'${ip}'"
  fi
  resp="$(printf "%s\n" "$req" \
    | timeout 15 openssl s_client -connect "${MANAGER_IP}:${AUTH_PORT}" -quiet 2>/dev/null \
    | tr -d '\r' | grep "OSSEC K:" || true)"
  printf "%s" "$resp"
}

while read -r name ip role group _rest; do
  case "$name" in ''|\#*) continue ;; esac
  group="${group:-default}"
  # These are DB-only simulated agents: agent_sim.py connects to remoted from the
  # manager host itself (127.0.0.1), NOT from the cosmetic fleet IP in fleet.txt.
  # If we register a fixed IP, remoted rejects every keepalive with
  # "(1408): Invalid ID <id> for the source ip: '127.0.0.1'" and the agents stay
  # "Never connected". Registering with IP 'any' lets them connect from anywhere.
  # The fleet.txt IP column is kept only for readability of the topology.
  ip="any"
  resp="$(enroll "$name" "$ip" "$group")"
  # resp = OSSEC K:'ID NAME IP KEY'
  key_body="${resp#*\'}"; key_body="${key_body%\'*}"
  if [ -z "$key_body" ] || [ "${key_body#* }" = "$key_body" ]; then
    echo "[!] enroll FAILED for $name (name may already exist, or authd password needed)" >&2
    continue
  fi
  id="${key_body%% *}"
  echo "$key_body" >> "$KEYS_OUT"
  train_agents="${train_agents:+$train_agents,}${id}:${name}"
  echo "[+] enrolled $name (role=$role) -> id $id"
done < "$FLEET_FILE"

chmod 600 "$KEYS_OUT"
echo
echo "[*] keys written to $KEYS_OUT ($(wc -l < "$KEYS_OUT") agents)"
echo "[*] add this to the training tool's env (/etc/wazuh-soc-training.env):"
echo "    TRAIN_AGENTS=${train_agents}"
