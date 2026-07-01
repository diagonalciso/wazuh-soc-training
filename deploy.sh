#!/usr/bin/env bash
# Deploy wazuh-soc-training to a Wazuh manager (must run there — local queue socket).
# Usage: ./deploy.sh user@10.10.0.10
set -euo pipefail
TARGET="${1:?usage: deploy.sh user@wazuh-host}"
APP=/opt/wazuh-soc-training

echo "[*] copying app to $TARGET:/tmp/wst-stage"
ssh "$TARGET" 'rm -rf /tmp/wst-stage && mkdir -p /tmp/wst-stage/scenarios /tmp/wst-stage/docs'
scp app.py injector.py scoring.py config.py wazuh-soc-training.service \
    wazuh-soc-training.env.example "$TARGET":/tmp/wst-stage/
scp scenarios/*.json "$TARGET":/tmp/wst-stage/scenarios/
scp docs/ADMIN.md "$TARGET":/tmp/wst-stage/docs/ 2>/dev/null || true

echo "[*] installing to $APP (sudo)"
ssh "$TARGET" "sudo mkdir -p $APP && sudo cp -r /tmp/wst-stage/* $APP/ && \
  ( [ -f /etc/wazuh-soc-training.env ] || sudo cp $APP/wazuh-soc-training.env.example /etc/wazuh-soc-training.env ) && \
  sudo chmod 600 /etc/wazuh-soc-training.env && \
  sudo cp $APP/wazuh-soc-training.service /etc/systemd/system/ && \
  sudo systemctl daemon-reload"

echo "[*] done. Edit /etc/wazuh-soc-training.env on the host, then:"
echo "    ssh $TARGET 'sudo systemctl enable --now wazuh-soc-training'"
echo "    curl -s http://<host>:8101/healthz"
