#!/usr/bin/env bash
# Remove all lab endpoints + the lab network. Optionally remove agents from
# the manager too (needs SSH to the manager).
#
#   ./teardown-lab.sh                 # remove containers + network
#   ./teardown-lab.sh --purge-manager user@10.10.0.10
set -euo pipefail
cd "$(dirname "$0")"
if [ -f lab.env ]; then
  set -a
  # shellcheck source=/dev/null
  . ./lab.env
  set +a
fi
NET="${LAB_NETWORK:-wazuh-lab}"
PREFIX="${NAME_PREFIX:-wlab-}"

echo "[*] removing containers ${PREFIX}*"
mapfile -t cs < <(docker ps -aq --filter "name=^/${PREFIX}")
if [ "${#cs[@]}" -gt 0 ]; then
  docker rm -f "${cs[@]}" >/dev/null || true
fi

if docker network inspect "$NET" >/dev/null 2>&1; then
  echo "[*] removing network $NET"
  docker network rm "$NET" >/dev/null || true
fi

if [ "${1:-}" = "--purge-manager" ] && [ -n "${2:-}" ]; then
  echo "[*] purging never_connected/disconnected agents on $2"
  ssh "$2" "sudo /var/ossec/bin/manage_agents -r \$(sudo /var/ossec/bin/agent_control -ln 2>/dev/null | awk '{print \$1}') 2>/dev/null || true"
fi
echo "[*] done."
