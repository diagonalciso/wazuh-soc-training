#!/usr/bin/env bash
# Deploy virtual endpoints (Wazuh agents in containers) against a REAL manager.
# Run this on a Docker host that can reach the manager on 1514/1515 tcp.
#
#   cp lab.env.example lab.env    # edit MANAGER_IP etc.
#   cp fleet.example.txt fleet.txt
#   ./deploy-lab.sh               # build image + start whole fleet
#   ./deploy-lab.sh web01         # (re)start a single endpoint
set -euo pipefail
cd "$(dirname "$0")"

[ -f lab.env ] || { echo "missing lab.env (cp lab.env.example lab.env)"; exit 1; }
set -a
# shellcheck source=/dev/null
. ./lab.env
set +a
: "${MANAGER_IP:?set MANAGER_IP in lab.env}"
FLEET_FILE="${FLEET_FILE:-fleet.txt}"
[ -f "$FLEET_FILE" ] || { echo "missing $FLEET_FILE (cp fleet.example.txt fleet.txt)"; exit 1; }

IMAGE="wazuh-lab-agent:${WAZUH_VERSION:-4.14.5}"
NET="${LAB_NETWORK:-wazuh-lab}"
SUBNET="${LAB_SUBNET:-172.30.0.0/24}"
PREFIX="${NAME_PREFIX:-wlab-}"
ONLY="${1:-}"

echo "[*] building agent image $IMAGE (agent $WAZUH_VERSION)"
docker build -q -t "$IMAGE" \
  --build-arg WAZUH_VERSION="${WAZUH_VERSION:-4.14.5}" \
  -f agent.Dockerfile . >/dev/null

if ! docker network inspect "$NET" >/dev/null 2>&1; then
  echo "[*] creating network $NET ($SUBNET)"
  docker network create --subnet "$SUBNET" "$NET" >/dev/null
fi

start_one() {
  local name="$1" ip="$2" role="$3" group="$4"
  local cname="${PREFIX}${name}"
  docker rm -f "$cname" >/dev/null 2>&1 || true
  echo "[*] $name  ip=$ip  role=$role  group=$group"
  docker run -d --name "$cname" --hostname "$name" \
    --network "$NET" --ip "$ip" \
    --restart unless-stopped \
    -e MANAGER_IP="$MANAGER_IP" \
    -e AGENT_NAME="$name" \
    -e AGENT_GROUP="$group" \
    -e ENROLL_PASSWORD="${ENROLL_PASSWORD:-}" \
    "$IMAGE" >/dev/null
}

count=0
while read -r name ip role group _rest; do
  [ -z "${name:-}" ] && continue
  case "$name" in \#*) continue;; esac
  group="${group:-default}"
  [ -n "$ONLY" ] && [ "$ONLY" != "$name" ] && continue
  start_one "$name" "$ip" "$role" "$group"
  count=$((count+1))
done < "$FLEET_FILE"

echo "[*] started $count endpoint(s). Give them ~30-60s to enroll."
echo "[*] verify on the manager:  /var/ossec/bin/agent_control -l"
echo "[*] or in the dashboard:    Agents -> should list the fleet as Active"
echo "[*] map names into training: TRAIN_AGENTS=\$(./agents-to-trainenv.sh)"
