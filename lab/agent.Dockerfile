# Virtual endpoint = one Wazuh agent in a container.
# Enrolls to a REAL Wazuh manager on start, then shows up as a live agent
# in the real dashboard. Agent version must be <= manager version.
FROM ubuntu:26.04

ARG WAZUH_VERSION=4.14.5
ENV DEBIAN_FRONTEND=noninteractive
# pipefail so the curl|gpg key import fails the build if curl fails
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# DL3008: transitive apt deps intentionally unpinned in this throwaway lab image
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl gnupg2 lsb-release ca-certificates procps iproute2 && \
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends wazuh-agent=${WAZUH_VERSION}-1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# MANAGER_IP, ENROLL_PASSWORD, AGENT_GROUP passed at run time.
ENTRYPOINT ["/entrypoint.sh"]
