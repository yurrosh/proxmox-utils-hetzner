#!/usr/bin/env bash
# docker-setup.sh — Install Docker CE + Compose on Debian 13
# Run inside VM as root.
#
# Usage: bash docker-setup.sh
#
# What it does:
#   1. Installs Docker CE from official repo
#   2. Installs Docker Compose plugin
#   3. Writes optimized /etc/docker/daemon.json (if not already present)
#   4. Enables and starts Docker
#   5. Verifies installation
set -euo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $1"; }
warn() { echo -e "  ${Y}!${N} $1"; }
err()  { echo -e "  ${R}✗${N} $1"; exit 1; }

[ "$(id -u)" -ne 0 ] && err "Must run as root"

echo -e "${W}docker-setup.sh — Install Docker CE${N}"
echo -e "${D}$(date '+%Y-%m-%d %H:%M:%S %Z')${N}"

# ── 1. Install Docker ──────────────────────────────────────────────
echo -e "\n${C}[1/4] Installing Docker CE${N}"

if command -v docker &>/dev/null; then
    warn "Docker already installed: $(docker --version)"
else
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Debian 13 Trixie — use bookworm repo if trixie not available yet
    CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-trixie}")
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    if ! apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null; then
        warn "Codename '${CODENAME}' not in Docker repo, falling back to bookworm"
        sed -i "s/${CODENAME}/bookworm/" /etc/apt/sources.list.d/docker.list
        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
    ok "Docker CE installed"
fi

# ── 2. daemon.json ─────────────────────────────────────────────────
echo -e "\n${C}[2/4] Configuring Docker daemon${N}"

DOCKER_JSON="/etc/docker/daemon.json"
if [ -f "$DOCKER_JSON" ] && grep -q '"live-restore"' "$DOCKER_JSON"; then
    warn "daemon.json already configured — skipping"
else
    mkdir -p /etc/docker
    cat > "$DOCKER_JSON" <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "5"
  },
  "storage-driver": "overlay2",
  "live-restore": true,
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 1048576, "Soft": 1048576 }
  },
  "metrics-addr": "127.0.0.1:9323"
}
EOF
    ok "Wrote $DOCKER_JSON"
fi

# ── 3. Enable and start ───────────────────────────────────────────
echo -e "\n${C}[3/4] Starting Docker${N}"

systemctl enable docker containerd &>/dev/null
systemctl restart docker
ok "Docker service running"

# ── 4. Verify ──────────────────────────────────────────────────────
echo -e "\n${C}[4/4] Verification${N}"

ok "Docker:  $(docker --version)"
ok "Compose: $(docker compose version)"
ok "Storage: $(docker info --format '{{.Driver}}')"
ok "Log:     json-file, 20m × 5 files"

echo ""
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo -e "${G} ✓ Docker ready${N}"
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${W}Quick start:${N}"
echo -e "    mkdir /opt/myapp && cd /opt/myapp"
echo -e "    vi docker-compose.yml"
echo -e "    docker compose up -d"
echo ""
