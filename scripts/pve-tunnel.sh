#!/usr/bin/env bash
# pve-tunnel.sh — Install Cloudflare Tunnel for Proxmox web UI + SSH access
# Run on the Proxmox HOST.
#
# Prerequisites:
#   1. Create a tunnel in Cloudflare Zero Trust dashboard:
#      https://one.dash.cloudflare.com → Networks → Tunnels → Create
#   2. Copy the tunnel token
#   3. Add public hostnames in the dashboard:
#      - pve-<host>.yourdomain.com → HTTPS://localhost:8006 (No TLS Verify)
#      - ssh-<host>.yourdomain.com → SSH://localhost:22
#   4. Create Access applications for both hostnames
#
# Usage:
#   bash pve-tunnel.sh <TOKEN>
#   bash pve-tunnel.sh --status
#   bash pve-tunnel.sh --uninstall
set -euo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $1"; }
warn() { echo -e "  ${Y}!${N} $1"; }
err()  { echo -e "  ${R}✗${N} $1"; }
info() { echo -e "  ${D}·${N} $1"; }

HOST_S=$(hostname -s)

echo -e "${W}pve-tunnel.sh — Cloudflare Tunnel for Proxmox${N}"
echo -e "${D}$(date '+%Y-%m-%d %H:%M:%S %Z') — ${HOST_S}${N}"

# ── Status check ────────────────────────────────────────────────────────
if [[ "${1:-}" == "--status" ]]; then
    echo ""
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        ok "cloudflared: running"
        systemctl status cloudflared --no-pager -l 2>/dev/null | head -10
    else
        err "cloudflared: not running"
    fi
    if command -v cloudflared &>/dev/null; then
        info "Version: $(cloudflared --version 2>/dev/null)"
    else
        err "cloudflared not installed"
    fi
    exit 0
fi

# ── Uninstall ───────────────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    echo ""
    systemctl stop cloudflared 2>/dev/null || true
    systemctl disable cloudflared 2>/dev/null || true
    cloudflared service uninstall 2>/dev/null || true
    apt-get remove -y cloudflared 2>/dev/null || dpkg -r cloudflared 2>/dev/null || true
    rm -f /etc/cloudflared/config.yml
    ok "cloudflared uninstalled"
    exit 0
fi

# ── Install ─────────────────────────────────────────────────────────────
TOKEN="${1:-}"
if [[ -z "$TOKEN" ]]; then
    echo ""
    echo "Usage: $0 <TUNNEL_TOKEN>"
    echo "       $0 --status"
    echo "       $0 --uninstall"
    echo ""
    echo "Steps to get a token:"
    echo "  1. Go to https://one.dash.cloudflare.com"
    echo "  2. Networks → Tunnels → Create a tunnel"
    echo "  3. Name it: ${HOST_S}-pve"
    echo "  4. Copy the token from the install command"
    echo "  5. Add public hostnames:"
    echo "     - pve-${HOST_S#up}.yourdomain.com → HTTPS://localhost:8006"
    echo "       (set 'No TLS Verify' + 'HTTP/2' in tunnel settings)"
    echo "     - ssh-${HOST_S#up}.yourdomain.com → SSH://localhost:22"
    echo "  6. Create Access applications for both hostnames"
    echo "     (email OTP or your preferred auth)"
    exit 1
fi

echo ""
echo -e "${C}[1/4] Installing cloudflared${N}"
if command -v cloudflared &>/dev/null; then
    info "Already installed: $(cloudflared --version 2>/dev/null)"
else
    DEB="/tmp/cloudflared.deb"
    curl -sSfL -o "$DEB" https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    dpkg -i "$DEB" >/dev/null
    rm -f "$DEB"
    ok "Installed $(cloudflared --version 2>/dev/null)"
fi

echo -e "\n${C}[2/4] Registering tunnel service${N}"
# Stop existing service if running
systemctl stop cloudflared 2>/dev/null || true
cloudflared service uninstall 2>/dev/null || true

cloudflared service install "$TOKEN"
ok "Service registered"

echo -e "\n${C}[3/4] Configuring SSH for browser terminal${N}"
# Allow password auth from localhost (cloudflared connects via 127.0.0.1)
SSH_MATCH="/etc/ssh/sshd_config.d/91-cloudflared.conf"
if [[ ! -f "$SSH_MATCH" ]]; then
    cat > "$SSH_MATCH" <<'EOF'
# Allow password auth from Cloudflare tunnel (browser SSH terminal)
Match Address 127.0.0.1,::1
    PasswordAuthentication yes
    PermitRootLogin yes
EOF
    if sshd -t 2>/dev/null; then
        systemctl reload sshd
        ok "SSH: password auth enabled from localhost only"
    else
        rm -f "$SSH_MATCH"
        warn "SSH config test failed — browser SSH may not work (key-only)"
    fi
else
    info "SSH localhost config already exists"
fi

echo -e "\n${C}[4/4] Verifying${N}"
sleep 2
if systemctl is-active --quiet cloudflared; then
    ok "cloudflared is running"
else
    err "cloudflared failed to start"
    journalctl -u cloudflared --no-pager -n 10
    exit 1
fi

echo ""
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo -e "${G} ✓ Cloudflare Tunnel active on ${HOST_S}${N}"
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${W}Next steps:${N}"
echo -e "    1. Verify web UI:  open your pve-*.yourdomain.com URL"
echo -e "    2. Verify SSH:     open your ssh-*.yourdomain.com URL"
echo -e "    3. Close port 8006 from public firewall:"
echo -e "       ${D}sed -i '/dport 8006/d' /etc/pve/firewall/cluster.fw${N}"
echo -e "       ${D}pve-firewall restart${N}"
echo ""
echo -e "  ${W}Mac terminal SSH (optional):${N}"
echo -e "    ${D}brew install cloudflared${N}"
echo -e "    Add to ~/.ssh/config:"
echo -e "    ${D}Host ${HOST_S#up}-ssh${N}"
echo -e "    ${D}    HostName ssh-${HOST_S#up}.yourdomain.com${N}"
echo -e "    ${D}    User root${N}"
echo -e "    ${D}    ProxyCommand cloudflared access ssh --hostname %h${N}"
echo ""
