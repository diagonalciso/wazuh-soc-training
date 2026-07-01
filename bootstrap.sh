#!/usr/bin/env bash
# One-shot lab bootstrap. Run as root ON the machine that will be the Wazuh
# server (a VM or bare metal). It:
#   1. installs a Wazuh all-in-one server (indexer + manager + dashboard) if absent
#   2. enrolls a fleet of DB-only agents (no endpoints -- just registrations)
#   3. starts the keepalive simulator so those agents show ACTIVE
#   4. installs + starts the wazuh-soc-training tool (drill launcher + scoring)
#
# The only real component is this one server. Endpoints/agents live only in the
# Wazuh DB; agent_sim.py fakes their keepalives, the queue-socket injector feeds
# their alerts. See docs/DEPLOY.md.
#
#   sudo ./bootstrap.sh                 # full lab (installs Wazuh if needed)
#   sudo ./bootstrap.sh --no-wazuh      # skip Wazuh install (already present)
#   sudo SKIP_FLEET=1 ./bootstrap.sh    # server + tool only, no fake agents
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/wazuh-soc-training"
ENV_FILE="/etc/wazuh-soc-training.env"
WAZUH_VERSION="${WAZUH_VERSION:-4.14}"
INSTALL_WAZUH=1
[ "${1:-}" = "--no-wazuh" ] && INSTALL_WAZUH=0

log() { printf '\n\033[1;36m[bootstrap] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[bootstrap] ERROR: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v python3 >/dev/null || die "python3 required"
command -v openssl >/dev/null || die "openssl required"
command -v curl    >/dev/null || die "curl required"

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$HOST_IP" ] || HOST_IP="127.0.0.1"

# ---------------------------------------------------------------- 1. Wazuh AIO
if [ "$INSTALL_WAZUH" = 1 ] && [ ! -d /var/ossec ]; then
  log "installing Wazuh all-in-one $WAZUH_VERSION (this is slow)"
  sysctl -w vm.max_map_count=262144 >/dev/null
  grep -q vm.max_map_count /etc/sysctl.conf || echo "vm.max_map_count=262144" >> /etc/sysctl.conf
  cd /root
  curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
  bash wazuh-install.sh -a -i
  log "Wazuh installed. admin password:"
  tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
    | grep -A1 "username: 'admin'" || echo "  (see /root/wazuh-install-files.tar)"
elif [ ! -d /var/ossec ]; then
  die "no /var/ossec and --no-wazuh given -- install Wazuh first"
else
  log "existing Wazuh detected at /var/ossec -- skipping install"
fi

QUEUE_SOCKET="/var/ossec/queue/sockets/queue"
[ -S "$QUEUE_SOCKET" ] || log "WARNING: $QUEUE_SOCKET not present yet (manager still starting?)"

# ---------------------------------------------------------------- 2. install tool
log "installing wazuh-soc-training to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -r "$REPO_DIR"/. "$INSTALL_DIR"/
find "$INSTALL_DIR" -name '*.db' -delete 2>/dev/null || true

# --------------------------------------------------- 2b. custom detection rules
# The Windows/Sysmon scenarios rely on training_rules.xml (see the file header
# for why the stock 60000-range rules can't fire on injected events).
if [ -f "$INSTALL_DIR/rules/training_rules.xml" ] && [ -d /var/ossec/etc/rules ]; then
  log "installing training detection rules"
  cp "$INSTALL_DIR/rules/training_rules.xml" /var/ossec/etc/rules/training_rules.xml
  chown wazuh:wazuh /var/ossec/etc/rules/training_rules.xml 2>/dev/null || true
  chmod 660 /var/ossec/etc/rules/training_rules.xml
  log "restarting wazuh-manager to load rules"
  systemctl restart wazuh-manager || die "manager failed to restart (bad rules?)"
  sleep 5
fi

# ---------------------------------------------------------------- 3. fleet + sim
TRAIN_AGENTS=""
if [ "${SKIP_FLEET:-0}" != 1 ]; then
  log "enrolling DB-only fleet + starting keepalive simulator"
  cd "$INSTALL_DIR/lab"
  [ -f fleet.txt ] || cp fleet.example.txt fleet.txt
  cat > lab.env <<EOF
MANAGER_IP=127.0.0.1
AUTH_PORT=1515
FLEET_FILE=fleet.txt
KEYS_OUT=$INSTALL_DIR/lab/agent_sim.keys
OSMAP_OUT=$INSTALL_DIR/lab/agent_sim.osmap
EOF
  # authd add-mode enrollment must be reachable; manager must be running.
  TRAIN_AGENTS="$(bash enroll-fleet.sh | awk -F= '/^ *TRAIN_AGENTS=/{print $2}')" || true
  # osmap is not secret but must be world-readable for the DynamicUser service.
  [ -f "$INSTALL_DIR/lab/agent_sim.osmap" ] && chmod 644 "$INSTALL_DIR/lab/agent_sim.osmap"

  install -m644 wazuh-agent-sim.service /etc/systemd/system/wazuh-agent-sim.service
  systemctl daemon-reload
  systemctl enable --now wazuh-agent-sim.service
  log "agent simulator running -- fleet should show ACTIVE within ~1 min"
else
  log "SKIP_FLEET set -- no fake agents"
fi

# ---------------------------------------------------------------- 4. tool env + svc
log "writing $ENV_FILE + starting training service"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
QUEUE_SOCKET=$QUEUE_SOCKET
WAZUH_DASHBOARD_URL=https://$HOST_IP
TRAIN_PORT=8101
TRAIN_BIND=0.0.0.0
TRAIN_DB=$INSTALL_DIR/training.db
TRAIN_AGENTS=$TRAIN_AGENTS
EOF
  chmod 600 "$ENV_FILE"
elif [ -n "$TRAIN_AGENTS" ]; then
  if grep -q '^TRAIN_AGENTS=' "$ENV_FILE"; then
    sed -i "s|^TRAIN_AGENTS=.*|TRAIN_AGENTS=$TRAIN_AGENTS|" "$ENV_FILE"
  else
    echo "TRAIN_AGENTS=$TRAIN_AGENTS" >> "$ENV_FILE"
  fi
fi

install -m644 "$INSTALL_DIR/wazuh-soc-training.service" /etc/systemd/system/wazuh-soc-training.service
systemctl daemon-reload
systemctl enable --now wazuh-soc-training.service

# ---------------------------------------------------------------- done
log "LAB READY"
cat <<EOF

  Wazuh dashboard : https://$HOST_IP        (user admin)
  Training tool   : http://$HOST_IP:8101/
  Fleet agents    : ${TRAIN_AGENTS:-<none>}

  Next: open the training tool, pick a scenario, hit Start -- injected alerts
  appear in the real dashboard for the (Active) fleet agents to triage.
EOF
