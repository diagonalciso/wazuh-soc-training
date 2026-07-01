#!/usr/bin/env bash
# Enroll this container as a Wazuh agent against a real manager, then run it.
set -euo pipefail

MANAGER_IP="${MANAGER_IP:?set MANAGER_IP to the real Wazuh manager}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"
ENROLL_PASSWORD="${ENROLL_PASSWORD:-}"
AGENT_GROUP="${AGENT_GROUP:-default}"

OSSEC=/var/ossec
CONF=$OSSEC/etc/ossec.conf

# point agent at the manager
sed -i "s#<address>.*</address>#<address>${MANAGER_IP}</address>#" "$CONF" || true

# enroll (idempotent: skip if a client.keys already exists)
if [ ! -s "$OSSEC/etc/client.keys" ]; then
  AUTH_ARGS=(-m "$MANAGER_IP" -A "$AGENT_NAME" -G "$AGENT_GROUP")
  [ -n "$ENROLL_PASSWORD" ] && AUTH_ARGS+=(-P "$ENROLL_PASSWORD")
  echo "[entrypoint] enrolling $AGENT_NAME -> $MANAGER_IP (group=$AGENT_GROUP)"
  for try in 1 2 3 4 5; do
    if "$OSSEC/bin/agent-auth" "${AUTH_ARGS[@]}"; then break; fi
    echo "[entrypoint] agent-auth failed (try $try), retrying in 5s..."; sleep 5
  done
fi

echo "[entrypoint] starting wazuh-agent"
"$OSSEC/bin/wazuh-control" start

# keep container alive + surface agent log as container stdout
exec tail -F "$OSSEC/logs/ossec.log"
