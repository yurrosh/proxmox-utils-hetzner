#!/usr/bin/env bash
# pve-network.sh — Set up NAT bridge for VM outbound internet
# Usage: bash pve-network.sh <config.toml>
# Reads [nat] section from TOML config.
# Idempotent — safe to re-run.
set -euo pipefail

# ---- Helpers ----
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; NC='\033[0m'
die()  { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }
ok()   { echo -e "  ${GRN}✓${NC} $*"; }
warn() { echo -e "  ${YEL}⚠${NC} $*"; }
info() { echo -e "  ${GRN}⊘${NC} $*"; }
step() { echo -e "${GRN}[$1/$TOTAL_STEPS]${NC} $2"; }

TOTAL_STEPS=4

# ---- Require config ----
CONF="${1:-}"
if [ -z "$CONF" ]; then
    die "Usage: bash pve-network.sh <config.toml>"
fi
if [ ! -f "$CONF" ]; then
    die "Config not found: $CONF"
fi

# ---- Minimal TOML parser (mawk-compatible) ----
parse_toml() {
    local file="$1" section="$2" key="$3" default="${4:-}"
    local val
    val=$(awk -v sec="[$section]" -v k="$key" '
        $0==sec{s=1;next} /^\[/{s=0}
        s && $0~"^"k"[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/,"")
            # Handle double-quoted values
            if (substr($0,1,1) == "\"") {
                sub(/^"/,""); sub(/".*$/,""); print; exit
            }
            # Handle single-quoted values
            if (substr($0,1,1) == "'\''") {
                sub(/^'\''/,""); sub(/'\''.*$/,""); print; exit
            }
            # Handle arrays: keep as-is (brackets included)
            if (/^\[/) { print; exit }
            # Unquoted: strip trailing comment and whitespace
            sub(/[[:space:]]*#.*$/, "")
            sub(/[[:space:]]+$/, "")
            print; exit
        }' "$file" 2>/dev/null)
    echo "${val:-$default}"
}

# ---- Load config ----
NAT_ENABLED=$(parse_toml "$CONF" nat enabled "true")
NAT_BRIDGE=$(parse_toml "$CONF" nat bridge "vmbr1")
NAT_ADDRESS=$(parse_toml "$CONF" nat address "10.10.10.1/24")
NAT_UPSTREAM=$(parse_toml "$CONF" nat upstream "vmbr0")
NAT_DNS1=$(parse_toml "$CONF" nat dns1 "1.1.1.1")
NAT_DNS2=$(parse_toml "$CONF" nat dns2 "8.8.8.8")

# Derive subnet from address (10.10.10.1/24 → 10.10.10.0/24)
NAT_GW="${NAT_ADDRESS%%/*}"
NAT_CIDR="${NAT_ADDRESS##*/}"
NAT_SUBNET=$(echo "$NAT_GW" | awk -F. -v cidr="$NAT_CIDR" '{
    if (cidr==24) printf "%s.%s.%s.0/%s\n",$1,$2,$3,cidr
    else if (cidr==16) printf "%s.%s.0.0/%s\n",$1,$2,cidr
    else printf "%s.%s.%s.0/%s\n",$1,$2,$3,cidr
}')

HOST_S=$(parse_toml "$CONF" server hostname "$(hostname -s)")

if [[ "$NAT_ENABLED" != "true" ]]; then
    echo "NAT disabled in config (nat.enabled = false). Nothing to do."
    exit 0
fi

echo -e "======= NAT Network Setup: ${HOST_S} ======="
echo "  Bridge:   ${NAT_BRIDGE} (${NAT_ADDRESS})"
echo "  Upstream: ${NAT_UPSTREAM}"
echo "  Subnet:   ${NAT_SUBNET}"
echo ""

# ===========================================================
# 1. IP forwarding
# ===========================================================
step 1 "IP forwarding"
SYSCTL_FILE="/etc/sysctl.d/99-proxmox-routing.conf"
if [ -f "$SYSCTL_FILE" ] && grep -q "ip_forward = 1" "$SYSCTL_FILE"; then
    info "Already configured in ${SYSCTL_FILE}"
else
    cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    ok "Created ${SYSCTL_FILE}"
fi
sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
ok "net.ipv4.ip_forward = $(sysctl -n net.ipv4.ip_forward)"

# ===========================================================
# 2. NAT bridge in /etc/network/interfaces
# ===========================================================
step 2 "NAT bridge (${NAT_BRIDGE})"
IFACES="/etc/network/interfaces"
if grep -q "iface ${NAT_BRIDGE}" "$IFACES"; then
    info "${NAT_BRIDGE} already in ${IFACES}"
else
    cat >> "$IFACES" <<EOF

auto ${NAT_BRIDGE}
iface ${NAT_BRIDGE} inet static
    address ${NAT_ADDRESS}
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    post-up   iptables -t nat -A POSTROUTING -s ${NAT_SUBNET} -o ${NAT_UPSTREAM} -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s ${NAT_SUBNET} -o ${NAT_UPSTREAM} -j MASQUERADE
EOF
    ok "Added ${NAT_BRIDGE} to ${IFACES}"
fi

# ===========================================================
# 3. Bring up bridge
# ===========================================================
step 3 "Activate bridge"
if ip link show "$NAT_BRIDGE" >/dev/null 2>&1; then
    info "${NAT_BRIDGE} already up"
    # Ensure masquerade rule exists (might be missing after reboot race)
    if ! iptables -t nat -C POSTROUTING -s "${NAT_SUBNET}" -o "${NAT_UPSTREAM}" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "${NAT_SUBNET}" -o "${NAT_UPSTREAM}" -j MASQUERADE
        ok "Restored masquerade rule"
    fi
else
    ifup "$NAT_BRIDGE"
    ok "${NAT_BRIDGE} activated"
fi

# ===========================================================
# 4. Verify
# ===========================================================
step 4 "Verify"
BRIDGE_IP=$(ip -4 addr show "$NAT_BRIDGE" 2>/dev/null | awk '/inet /{print $2}')
if [[ "$BRIDGE_IP" == "$NAT_ADDRESS" ]]; then
    ok "${NAT_BRIDGE} = ${BRIDGE_IP}"
else
    die "${NAT_BRIDGE} address mismatch: expected ${NAT_ADDRESS}, got ${BRIDGE_IP:-NONE}"
fi

if iptables -t nat -C POSTROUTING -s "${NAT_SUBNET}" -o "${NAT_UPSTREAM}" -j MASQUERADE 2>/dev/null; then
    ok "MASQUERADE: ${NAT_SUBNET} → ${NAT_UPSTREAM}"
else
    die "Masquerade rule missing!"
fi

FWD=$(sysctl -n net.ipv4.ip_forward)
if [[ "$FWD" == "1" ]]; then
    ok "IP forwarding active"
else
    die "IP forwarding not enabled!"
fi

echo ""
echo "============================================"
echo " NAT ready: ${NAT_BRIDGE} (${NAT_SUBNET})"
echo "============================================"
echo "VM network settings:"
echo "  Bridge:  ${NAT_BRIDGE}"
echo "  IP:      ${NAT_GW%.*}.x/${NAT_CIDR}  (pick 2-254)"
echo "  Gateway: ${NAT_GW}"
echo "  DNS:     ${NAT_DNS1}, ${NAT_DNS2}"
