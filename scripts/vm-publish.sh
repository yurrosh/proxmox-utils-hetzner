#!/usr/bin/env bash
# vm-publish.sh — Attach a Hetzner public IP to a Proxmox VM
# Run on the Proxmox HOST.
#
# Prerequisites:
#   1. Order additional IP in Hetzner Robot (robot.hetzner.com → Server → IPs)
#   2. Request virtual MAC for that IP (type: Linux/Other)
#
# Usage (TOML config — preferred):
#   bash vm-publish.sh <config.toml> [--apply]
#   Reads [vm].vmid and [publish] section from TOML.
#
# Usage (positional args — legacy):
#   bash vm-publish.sh <VMID> <PUBLIC_IP> <VIRTUAL_MAC> [--apply]
#
# Without --apply, the script shows what it would do (dry run).
# With --apply, it configures the VM and prepares the guest setup script.
#
# After running with --apply:
#   1. Reboot the VM (or hotplug if supported)
#   2. SSH into the VM via its internal IP
#   3. Run: bash /tmp/vm-guest-publish.sh
#   4. Verify from outside: ssh root@<PUBLIC_IP>
set -euo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $1"; }
warn() { echo -e "  ${Y}!${N} $1"; }
err()  { echo -e "  ${R}✗${N} $1"; }
info() { echo -e "  ${D}·${N} $1"; }

# ── TOML parser ─────────────────────────────────────────────────────────
parse_toml() {
    local file="$1" section="$2" key="$3" default="${4:-}"
    local val
    val=$(awk -v sec="[$section]" -v k="$key" '
        $0==sec{s=1;next} /^\[/{s=0}
        s && $0~"^"k"[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/,"")
            if (substr($0,1,1) == "\"") { sub(/^"/,""); sub(/".*$/,""); print; exit }
            if (substr($0,1,1) == "'\''") { sub(/^'\''/,""); sub(/'\''.*$/,""); print; exit }
            sub(/[[:space:]]*#.*$/, ""); sub(/[[:space:]]+$/, ""); print; exit
        }' "$file" 2>/dev/null)
    echo "${val:-$default}"
}

# ── Parse arguments ─────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 <config.toml> [--apply]"
    echo "       $0 <VMID> <PUBLIC_IP> <VIRTUAL_MAC> [--apply]"
    echo ""
    echo "  TOML mode:   Reads [vm].vmid and [publish] section"
    echo "  Legacy mode: Positional VMID, IP, MAC arguments"
    echo "  --apply      Actually make changes (default: dry run)"
    exit 1
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage
[ $# -lt 1 ] && usage

APPLY=false

# Detect mode: TOML file or positional args
if [[ -f "$1" ]] && [[ "$1" == *.toml ]]; then
    # ── TOML mode ──
    CONFIG="$1"
    [ "${2:-}" = "--apply" ] && APPLY=true

    VMID=$(parse_toml "$CONFIG" vm vmid "")
    PUBLIC_IP=$(parse_toml "$CONFIG" publish public_ip "")
    VIRTUAL_MAC=$(parse_toml "$CONFIG" publish mac "")
    PUB_GW_OVERRIDE=$(parse_toml "$CONFIG" publish public_gw "")

    [ -z "$VMID" ] && { echo -e "${R}Missing [vm] vmid in $CONFIG${N}"; exit 1; }
    [ -z "$PUBLIC_IP" ] && { echo -e "${R}Missing [publish] public_ip in $CONFIG${N}"; exit 1; }
    [ -z "$VIRTUAL_MAC" ] && { echo -e "${R}Missing [publish] mac in $CONFIG${N}"; exit 1; }

    # Strip CIDR if present (user may write 65.109.64.200/32)
    PUBLIC_IP="${PUBLIC_IP%%/*}"
else
    # ── Legacy positional mode ──
    [ $# -lt 3 ] && usage
    VMID="$1"
    PUBLIC_IP="$2"
    VIRTUAL_MAC="$3"
    PUB_GW_OVERRIDE=""
    [ "${4:-}" = "--apply" ] && APPLY=true
fi

echo -e "${W}vm-publish.sh — Attach public IP to VM${N}"
echo -e "${D}$(date '+%Y-%m-%d %H:%M:%S %Z')${N}"

# ── Validate inputs ─────────────────────────────────────────────────────
echo -e "\n${C}[1/5] Validating inputs${N}"

# Check running as root on Proxmox
if [ "$(id -u)" -ne 0 ]; then
    err "Must run as root on the Proxmox host"
    exit 1
fi

if ! command -v qm &>/dev/null; then
    err "qm not found — this script must run on a Proxmox host"
    exit 1
fi

# Check VM exists
if ! qm status "$VMID" &>/dev/null; then
    err "VM $VMID does not exist"
    exit 1
fi

VM_STATUS=$(qm status "$VMID" | awk '{print $2}')
VM_NAME=$(grep '^name:' "/etc/pve/qemu-server/${VMID}.conf" | awk '{print $2}')
ok "VM $VMID ($VM_NAME) — status: $VM_STATUS"

# Validate IP format
if ! echo "$PUBLIC_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
    err "Invalid IP format: $PUBLIC_IP"
    exit 1
fi
ok "Public IP: $PUBLIC_IP"

# Validate MAC format
MAC_UPPER=$(echo "$VIRTUAL_MAC" | tr '[:lower:]' '[:upper:]')
if ! echo "$MAC_UPPER" | grep -qE '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'; then
    err "Invalid MAC format: $VIRTUAL_MAC"
    exit 1
fi
ok "Virtual MAC: $MAC_UPPER"

# ── Detect host gateway ────────────────────────────────────────────────
echo -e "\n${C}[2/5] Detecting network configuration${N}"

HOST_GW=$(ip route | awk '/^default/{print $3}' | head -1)
HOST_IP=$(ip -4 addr show vmbr0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
PUBLIC_BRIDGE="vmbr0"

# Use explicit gateway from TOML if provided, otherwise auto-detect
if [ -n "${PUB_GW_OVERRIDE:-}" ]; then
    HOST_GW="$PUB_GW_OVERRIDE"
    ok "Gateway from config: $HOST_GW"
elif [ -z "$HOST_GW" ]; then
    err "Cannot detect host default gateway"
    exit 1
fi
ok "Host IP: $HOST_IP"
ok "Host gateway: $HOST_GW (will be used as VM gateway)"
ok "Public bridge: $PUBLIC_BRIDGE"

# Check VM internal IP (for SSH access)
VM_INTERNAL_IP=""
for IP_LINE in $(grep '^ipconfig' "/etc/pve/qemu-server/${VMID}.conf" | grep -oP 'ip=\K[^/,]+'); do
    if echo "$IP_LINE" | grep -q '^10\.'; then
        VM_INTERNAL_IP="$IP_LINE"
        break
    fi
done
if [ -n "$VM_INTERNAL_IP" ]; then
    ok "VM internal IP: $VM_INTERNAL_IP (for SSH access)"
else
    warn "Cannot detect VM internal IP — you'll need to SSH manually"
fi

# ── Find free NIC slot ──────────────────────────────────────────────────
echo -e "\n${C}[3/5] Checking VM network interfaces${N}"

# Show existing NICs
grep '^net[0-9]' "/etc/pve/qemu-server/${VMID}.conf" | while read -r line; do
    info "$line"
done

# Find first free netX slot
FREE_NIC=""
for i in $(seq 0 7); do
    if ! grep -q "^net${i}:" "/etc/pve/qemu-server/${VMID}.conf"; then
        FREE_NIC="net${i}"
        break
    fi
done

if [ -z "$FREE_NIC" ]; then
    err "No free NIC slots (net0-net7 all used)"
    exit 1
fi
ok "Will use slot: $FREE_NIC"

# Check if this VM already has a NIC on the public bridge
if grep "^net[0-9].*bridge=${PUBLIC_BRIDGE}" "/etc/pve/qemu-server/${VMID}.conf" | grep -qi "$MAC_UPPER"; then
    warn "VM already has a NIC with MAC $MAC_UPPER on $PUBLIC_BRIDGE"
fi

# ── Show plan / apply ──────────────────────────────────────────────────
echo -e "\n${C}[4/5] $([ "$APPLY" = true ] && echo "Applying changes" || echo "Dry run (add --apply to execute)")${N}"

echo ""
echo -e "  ${W}Proxmox (host):${N}"
echo -e "    qm set $VMID --${FREE_NIC} virtio=${MAC_UPPER},bridge=${PUBLIC_BRIDGE}"
echo ""
echo -e "  ${W}Guest config:${N} netplan (Debian 13+) or ifupdown (Debian 12)"
echo -e "    address ${PUBLIC_IP}/32"
echo -e "    gateway ${HOST_GW}"
echo ""

if [ "$APPLY" = false ]; then
    echo -e "${Y}Dry run complete. Add --apply to execute.${N}"
    exit 0
fi

# ── Apply: add NIC to VM ───────────────────────────────────────────────
qm set "$VMID" --"${FREE_NIC}" "virtio=${MAC_UPPER},bridge=${PUBLIC_BRIDGE}"
ok "Added ${FREE_NIC} (virtio, MAC=${MAC_UPPER}, bridge=${PUBLIC_BRIDGE})"

# ── Generate guest setup script ────────────────────────────────────────
echo -e "\n${C}[5/5] Generating guest setup script${N}"

GUEST_SCRIPT="/tmp/vm-guest-publish-${VMID}.sh"
cat > "$GUEST_SCRIPT" <<GUESTEOF
#!/usr/bin/env bash
# vm-guest-publish.sh — Configure public IP + firewall inside the VM
# Generated by vm-publish.sh on $(date '+%Y-%m-%d %H:%M:%S %Z')
# Run inside VM $VMID ($VM_NAME) as root.
set -euo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'
ok()   { echo -e "  \${G}✓\${N} \$1"; }
warn() { echo -e "  \${Y}!\${N} \$1"; }
err()  { echo -e "  \${R}✗\${N} \$1"; exit 1; }

PUBLIC_IP="${PUBLIC_IP}"
GATEWAY="${HOST_GW}"
INTERNAL_NET="10.10.10.0/24"

echo -e "\${W}vm-guest-publish.sh — Public IP + Firewall setup\${N}"
echo -e "\${D}\$(date '+%Y-%m-%d %H:%M:%S %Z')\${N}"

# ── 1. Detect the new public NIC ────────────────────────────────────
echo -e "\n\${C}[1/6] Detecting public network interface\${N}"

PUBLIC_NIC=""
INTERNAL_NIC=""
for iface in \$(ls /sys/class/net/ | grep -vE '^(lo|docker|br-|veth)'); do
    # Check if this interface is on the internal network
    if ip addr show "\$iface" 2>/dev/null | grep -q '10.10.10.'; then
        INTERNAL_NIC="\$iface"
    elif [ -z "\$PUBLIC_NIC" ] && [ "\$iface" != "lo" ]; then
        # Unconfigured interface = likely the new public NIC
        if ! ip addr show "\$iface" 2>/dev/null | grep -q 'inet '; then
            PUBLIC_NIC="\$iface"
        fi
    fi
done

if [ -z "\$PUBLIC_NIC" ]; then
    # Fallback: look for second virtio NIC
    for iface in eth1 ens19 enp0s19; do
        if [ -d "/sys/class/net/\$iface" ]; then
            PUBLIC_NIC="\$iface"
            break
        fi
    done
fi

[ -z "\$PUBLIC_NIC" ] && err "Cannot find unconfigured public NIC. Did you reboot after adding the NIC in Proxmox?"
[ -z "\$INTERNAL_NIC" ] && INTERNAL_NIC="eth0"

ok "Public NIC:   \$PUBLIC_NIC"
ok "Internal NIC: \$INTERNAL_NIC"

# ── 2. Configure public interface ───────────────────────────────────
echo -e "\n\${C}[2/6] Configuring \$PUBLIC_NIC with \$PUBLIC_IP\${N}"

# Detect network manager: netplan (Debian 13+) or ifupdown (Debian 12)
USE_NETPLAN=false
if command -v netplan &>/dev/null && [ -d /etc/netplan ]; then
    USE_NETPLAN=true
fi

# Cloud-init may manage networking — disable to prevent conflicts
mkdir -p /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg <<CLOUDEOF
network: {config: disabled}
CLOUDEOF
ok "Disabled cloud-init network management"

# Get the MAC address of the public NIC for matching
PUB_MAC=\$(cat "/sys/class/net/\$PUBLIC_NIC/address" 2>/dev/null | tr '[:upper:]' '[:lower:]')

if \$USE_NETPLAN; then
    # ── Netplan (Debian 13 / Trixie) ──
    cat > /etc/netplan/60-public.yaml <<NPEOF
network:
  version: 2
  ethernets:
    \$PUBLIC_NIC:
      match:
        macaddress: "\$PUB_MAC"
      addresses:
        - "\${PUBLIC_IP}/32"
      nameservers:
        addresses:
          - 1.1.1.1
          - 8.8.8.8
      routes:
        - to: "default"
          via: "\$GATEWAY"
        - to: "\${GATEWAY}/32"
          scope: link
      set-name: "\$PUBLIC_NIC"
NPEOF
    chmod 600 /etc/netplan/60-public.yaml
    ok "Wrote /etc/netplan/60-public.yaml"

    # Remove default route + routes block from internal interface netplan
    # Uses python3 for safe YAML editing (avoids sed breaking YAML structure)
    for f in /etc/netplan/50-cloud-init.yaml /etc/netplan/*.yaml; do
        [ -f "\$f" ] && [ "\$f" != "/etc/netplan/60-public.yaml" ] || continue
        python3 -c "
import yaml, sys
with open('\$f') as fh:
    cfg = yaml.safe_load(fh)
if not cfg or 'network' not in cfg:
    sys.exit(0)
changed = False
for name, eth in cfg.get('network',{}).get('ethernets',{}).items():
    if 'routes' in eth:
        eth['routes'] = [r for r in eth['routes'] if r.get('to') != 'default']
        if not eth['routes']:
            del eth['routes']
        changed = True
    if 'gateway4' in eth:
        del eth['gateway4']
        changed = True
if changed:
    with open('\$f','w') as fh:
        yaml.dump(cfg, fh, default_flow_style=False)
" 2>/dev/null || true
    done
    ok "Removed default gateway from internal interface configs"

    netplan apply 2>/dev/null
    ok "Netplan applied — \$PUBLIC_NIC is up"
else
    # ── ifupdown (Debian 12 / Bookworm) ──
    cat > /etc/network/interfaces.d/public <<NETEOF
# Public interface — Hetzner additional IP
# Configured by vm-guest-publish.sh
auto \$PUBLIC_NIC
iface \$PUBLIC_NIC inet static
    address \${PUBLIC_IP}/32
    gateway \$GATEWAY
    pointopoint \$GATEWAY
NETEOF
    ok "Wrote /etc/network/interfaces.d/public"

    # Remove default gateway from internal interface
    if [ -f /etc/network/interfaces.d/internal ]; then
        sed -i '/^\s*gateway/d' /etc/network/interfaces.d/internal
        ok "Removed gateway from internal interface config"
    fi

    ifup "\$PUBLIC_NIC" 2>/dev/null || {
        ip addr add \${PUBLIC_IP}/32 dev "\$PUBLIC_NIC"
        ip link set "\$PUBLIC_NIC" up
        ip route add \$GATEWAY dev "\$PUBLIC_NIC"
        ip route add default via \$GATEWAY dev "\$PUBLIC_NIC"
    }
    ok "Interface \$PUBLIC_NIC is up"
fi

# ── 3. Fix routing ─────────────────────────────────────────────────
echo -e "\n\${C}[3/6] Configuring routing\${N}"

# Ensure internal network is reachable via internal NIC
ip route replace \$INTERNAL_NET dev "\$INTERNAL_NIC" 2>/dev/null || true

# Verify default route goes via public NIC
DEFAULT_DEV=\$(ip route | awk '/^default/{print \$5}' | head -1)
if [ "\$DEFAULT_DEV" = "\$PUBLIC_NIC" ]; then
    ok "Default route via \$PUBLIC_NIC (public)"
else
    warn "Default route via \$DEFAULT_DEV — expected \$PUBLIC_NIC"
    warn "Outbound traffic may use wrong source IP"
fi

# Test connectivity
if ping -c 1 -W 3 -I "\$PUBLIC_NIC" 1.1.1.1 &>/dev/null; then
    ok "Internet reachable via \$PUBLIC_NIC"
else
    warn "Cannot ping 1.1.1.1 via \$PUBLIC_NIC — check Hetzner MAC/IP assignment"
fi

DETECTED_IP=\$(curl -4 -s --interface "\$PUBLIC_NIC" --max-time 5 ifconfig.me 2>/dev/null || echo "unknown")
if [ "\$DETECTED_IP" = "\$PUBLIC_IP" ]; then
    ok "External IP confirmed: \$DETECTED_IP"
else
    warn "External IP mismatch: got \$DETECTED_IP, expected \$PUBLIC_IP"
fi

# ── 4. Install & configure nftables firewall ────────────────────────
echo -e "\n\${C}[4/6] Configuring nftables firewall\${N}"

# Install if needed
if ! command -v nft &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq nftables
fi

# Backup existing rules
[ -f /etc/nftables.conf ] && cp /etc/nftables.conf /etc/nftables.conf.bak.\$(date +%s)

cat > /etc/nftables.conf <<'NFTEOF'
#!/usr/sbin/nft -f
# Production firewall — vm-guest-publish.sh
# Default: deny all inbound, allow all outbound
# Per-IP SSH blocking handled by fail2ban.
# Edit the "Public services" section to open ports.
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback
        iif "lo" accept

        # Connection tracking
        ct state established,related accept
        ct state invalid drop

        # ICMP — rate limited
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
        ip6 nexthdr icmpv6 accept

        # Internal network — full trust
        ip saddr 10.10.10.0/24 accept

        # Docker bridge
        ip saddr 172.16.0.0/12 accept

        # ── Public services (edit this section) ─────────────────
        tcp dport { 80, 443 } accept
        tcp dport 22 ct state new limit rate 5/minute accept
        # Uncomment as needed:
        # tcp dport 8080 accept              # Alt HTTP
        # tcp dport { 25, 587, 465 } accept  # Mail
        # udp dport 51820 accept             # WireGuard
        # ────────────────────────────────────────────────────────
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
    }
}
NFTEOF

# Apply and enable
nft -f /etc/nftables.conf
systemctl enable nftables &>/dev/null
ok "nftables firewall active — default deny inbound"
ok "Open ports: 22 (rate-limited), 80, 443"

# ── 5. Harden SSH ──────────────────────────────────────────────────
echo -e "\n\${C}[5/6] Hardening SSH\${N}"

SSH_CONF="/etc/ssh/sshd_config.d/90-hardening.conf"
if [ -f "\$SSH_CONF" ]; then
    warn "\$SSH_CONF already exists — skipping"
else
    cat > "\$SSH_CONF" <<'SSHEOF'
# vm-guest-publish.sh — SSH hardening for public-facing VM
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
SSHEOF
    # Verify config is valid before reloading
    if sshd -t 2>/dev/null; then
        systemctl reload sshd
        ok "SSH hardened: key-only auth, no passwords, no X11"
    else
        rm -f "\$SSH_CONF"
        warn "SSH config test failed — reverted. Check manually."
    fi
fi

# ── 6. Install fail2ban ────────────────────────────────────────────
echo -e "\n\${C}[6/6] fail2ban\${N}"

if command -v fail2ban-server &>/dev/null; then
    skip "fail2ban already installed"
else
    if apt-get install -y -qq fail2ban 2>/dev/null; then
        # Configure for nftables backend
        mkdir -p /etc/fail2ban
        cat > /etc/fail2ban/jail.local <<'F2BEOF'
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
backend = systemd
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
mode = aggressive
F2BEOF
        systemctl enable fail2ban &>/dev/null
        systemctl restart fail2ban &>/dev/null
        ok "fail2ban installed — nftables backend, 1h ban after 5 failures"
    else
        warn "fail2ban install failed — not critical, nftables rate limiting still active"
    fi
fi

# ── Summary ────────────────────────────────────────────────────────
echo ""
echo -e "\${W}═══════════════════════════════════════════════════\${N}"
echo -e "\${G} ✓ VM is now publicly accessible\${N}"
echo -e "\${W}═══════════════════════════════════════════════════\${N}"
echo ""
echo -e "  \${W}Public IP:\${N}     \$PUBLIC_IP"
echo -e "  \${W}Interface:\${N}     \$PUBLIC_NIC"
echo -e "  \${W}Gateway:\${N}       \$GATEWAY"
echo -e "  \${W}Internal IP:\${N}   \$(ip addr show \$INTERNAL_NIC | awk '/inet /{print \$2}' | head -1)"
echo ""
echo -e "  \${W}Firewall:\${N}      nftables (default deny)"
echo -e "  \${W}Open ports:\${N}    22 (SSH, rate-limited), 80, 443"
echo -e "  \${W}SSH auth:\${N}      Key-only (passwords disabled)"
echo -e "  \${W}fail2ban:\${N}      Active (1h ban / 5 failures)"
echo ""
echo -e "  \${C}Remaining steps:\${N}"
echo -e "    1. Set reverse DNS in Hetzner Robot: \$PUBLIC_IP → your.domain.com"
echo -e "    2. Create DNS A record: your.domain.com → \$PUBLIC_IP"
echo -e "    3. Test from outside: ssh root@\$PUBLIC_IP"
echo -e "    4. Edit /etc/nftables.conf to open additional ports as needed"
echo ""
GUESTEOF

chmod +x "$GUEST_SCRIPT"
ok "Generated guest script: $GUEST_SCRIPT"

# Try to SCP it to the VM
if [ -n "$VM_INTERNAL_IP" ]; then
    if scp -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q \
        "$GUEST_SCRIPT" "root@${VM_INTERNAL_IP}:/tmp/vm-guest-publish.sh" 2>/dev/null; then
        ok "Copied to VM: /tmp/vm-guest-publish.sh"
    else
        warn "Could not SCP to VM — copy manually:"
        echo -e "       ${D}scp ${GUEST_SCRIPT} root@${VM_INTERNAL_IP}:/tmp/vm-guest-publish.sh${N}"
    fi
fi

# ── Final instructions ──────────────────────────────────────────────
echo ""
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo -e "${G} ✓ Host-side configuration complete${N}"
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${W}Next steps:${N}"
echo ""
if [ "$VM_STATUS" = "running" ]; then
    echo -e "    1. Reboot the VM for the new NIC to appear:"
    echo -e "       ${D}qm reboot $VMID${N}"
else
    echo -e "    1. Start the VM:"
    echo -e "       ${D}qm start $VMID${N}"
fi
echo ""
echo -e "    2. Copy guest script (if SCP failed above):"
echo -e "       ${D}scp ${GUEST_SCRIPT} root@${VM_INTERNAL_IP:-<INTERNAL_IP>}:/tmp/vm-guest-publish.sh${N}"
echo ""
echo -e "    3. SSH into the VM and run the guest setup:"
echo -e "       ${D}ssh root@${VM_INTERNAL_IP:-<INTERNAL_IP>}${N}"
echo -e "       ${D}bash /tmp/vm-guest-publish.sh${N}"
echo ""
echo -e "    4. Verify from your workstation:"
echo -e "       ${D}ssh root@${PUBLIC_IP}${N}"
echo -e "       ${D}curl -I http://${PUBLIC_IP}${N}"
echo -e "       ${D}nmap -Pn ${PUBLIC_IP}${N}"
echo ""
