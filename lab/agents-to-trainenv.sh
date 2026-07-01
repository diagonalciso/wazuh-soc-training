#!/usr/bin/env bash
# Print a TRAIN_AGENTS=id:name,... line from the manager's real agent list,
# so the training tool uses the ids the manager actually assigned.
#
#   ./agents-to-trainenv.sh user@10.10.0.10
#   ./agents-to-trainenv.sh user@10.10.0.10 | sudo tee -a /etc/wazuh-soc-training.env
set -euo pipefail
TARGET="${1:?usage: agents-to-trainenv.sh user@manager}"

# agent_control -l lines look like:  ID: 001, Name: web01, IP: any, Active
pairs=$(ssh "$TARGET" 'sudo /var/ossec/bin/agent_control -l' 2>/dev/null \
  | sed -n 's/.*ID:[[:space:]]*\([0-9]\+\),[[:space:]]*Name:[[:space:]]*\([^,]*\),.*/\1:\2/p' \
  | grep -v ':00[0-9]*:.*manager' || true)

# drop the manager's own entry (id 000) and trim spaces
pairs=$(echo "$pairs" | awk -F: '$1!="000"{gsub(/ /,"",$2);print $1":"$2}' | paste -sd, -)

[ -z "$pairs" ] && { echo "no agents found on $TARGET" >&2; exit 1; }
echo "TRAIN_AGENTS=$pairs"
