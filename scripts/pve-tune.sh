#!/bin/bash
# pve-tune.sh — Performance tuning for Proxmox VE hosts
# Applies kernel, network, memory, and scheduler optimizations.
# All changes are idempotent and safe for production.
#
# Usage: bash pve-tune.sh
#        bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-tune.sh)
# Repo:  https://github.com/yurrosh/proxmox-utils-hetzner
#
# What this does:
#   - TCP BBR congestion control + fq qdisc
#   - Network buffer & backlog tuning
#   - TCP keepalive, fastopen, ephemeral port range
#   - Kernel panic auto-reboot (critical for remote/datacenter)
#   - Scheduler tuning for hypervisor workloads
#   - VM dirty page writeback tuning
#   - Memory reserve for OOM prevention
#   - NIC ring buffer increase (if supported)
#   - Cleanup of ad-hoc sysctl files from earlier manual tuning
#
# Does NOT touch:
#   - Firewall / conntrack (managed by pve-harden.sh)
#   - IP forwarding / routing (managed by pve-network.sh)
#   - ZFS ARC limits (managed by pve-harden.sh)
#   - Guest-side tuning (managed by vm-optimize.sh)

set -euo pipefail

CLR_GREEN="\033[1;32m"
CLR_YELLOW="\033[1;33m"
CLR_BLUE="\033[1;34m"
CLR_WHITE="\033[1;37m"
CLR_DIM="\033[0;90m"
CLR_RESET="\033[m"

if [[ $EUID -ne 0 ]]; then echo -e "\033[1;31mMust run as root\033[m"; exit 1; fi

HOST_S=$(hostname -s)
TOTAL_STEPS=6

step() { echo -e "${CLR_BLUE}[$1/${TOTAL_STEPS}] $2${CLR_RESET}"; }
ok()   { echo -e "  ${CLR_GREEN}✓${CLR_RESET} $1"; }
skip() { echo -e "  ${CLR_DIM}⊘${CLR_RESET} $1"; }

echo ""
echo -e "${CLR_WHITE}pve-tune.sh — Performance tuning: ${HOST_S}${CLR_RESET}"
echo -e "${CLR_DIM}$(date '+%Y-%m-%d %H:%M:%S %Z')${CLR_RESET}"
echo ""

# ===========================================================
# 1. TCP BBR congestion control
# ===========================================================
step 1 "TCP BBR congestion control"

# Load BBR module
if lsmod | grep -q tcp_bbr; then
    skip "tcp_bbr module already loaded"
else
    modprobe tcp_bbr
    ok "tcp_bbr module loaded"
fi

# Persist module across reboots
if grep -rqs '^tcp_bbr' /etc/modules-load.d/ 2>/dev/null; then
    skip "tcp_bbr persistence already configured"
else
    echo 'tcp_bbr' > /etc/modules-load.d/tcp-bbr.conf
    ok "tcp_bbr persisted in /etc/modules-load.d/tcp-bbr.conf"
fi

# Verify availability
AVAIL=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
if echo "$AVAIL" | grep -q bbr; then
    ok "BBR available: ${AVAIL}"
else
    echo -e "  ${CLR_YELLOW}⚠ BBR not in available list: ${AVAIL}${CLR_RESET}"
    echo -e "  ${CLR_YELLOW}  Reboot may be needed for module to register${CLR_RESET}"
fi

# ===========================================================
# 2. Sysctl: network, kernel, memory tuning
# ===========================================================
step 2 "Sysctl performance tuning"

TOTAL_RAM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo)
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

# Scale min_free_kbytes: 256MB for ≥64GB RAM, 128MB otherwise
# Protects against OOM during ZFS ARC pressure spikes
if [ "$TOTAL_RAM_GB" -ge 64 ]; then
    MIN_FREE_KB=262144
else
    MIN_FREE_KB=131072
fi

# Scale network buffers: 16MB for ≤1Gbps, 32MB for 10Gbps+
# Detect first physical NIC (exclude virtual bridges, taps, loopback)
PHYS_NIC=$(ls /sys/class/net/ | grep -v -E '^(lo|vmbr|tap|fwbr|fwln|fwpr|bond|dummy)' | head -1)
LINK_SPEED=""
if [ -n "${PHYS_NIC:-}" ]; then
    LINK_SPEED=$(ethtool "$PHYS_NIC" 2>/dev/null | awk '/Speed:/{gsub(/[^0-9]/,"",$2); print $2}')
fi
if [ "${LINK_SPEED:-1000}" -ge 10000 ]; then
    SOCK_BUF_MAX=33554432   # 32MB for 10G+
else
    SOCK_BUF_MAX=16777216   # 16MB for 1G
fi

cat > /etc/sysctl.d/90-pve-tune.conf << SYSCTL
# pve-tune.sh — Proxmox VE host performance tuning
# Generated: $(date '+%Y-%m-%d %H:%M:%S') on ${HOST_S}
# RAM: ${TOTAL_RAM_GB}GB, NIC: ${PHYS_NIC:-unknown} @ ${LINK_SPEED:-unknown}Mbps

# ── TCP congestion control ──────────────────────────────────
# BBR: model-based (not loss-based like CUBIC), better throughput
# on lossy links and lower latency on buffered paths.
# fq qdisc is required for BBR pacing to work correctly.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# ── Network buffers ─────────────────────────────────────────
# Default 208K max is far too low — limits TCP window scaling.
# Allocated on demand per-socket, not upfront.
net.core.rmem_max = ${SOCK_BUF_MAX}
net.core.wmem_max = ${SOCK_BUF_MAX}
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# TCP autotuning range: min / default / max
# Max must match socket buffer max for autotuning to reach full speed.
net.ipv4.tcp_rmem = 4096 131072 ${SOCK_BUF_MAX}
net.ipv4.tcp_wmem = 4096 16384 ${SOCK_BUF_MAX}

# Backlog queue — default 1000 too low for bridged VM traffic bursts
net.core.netdev_max_backlog = 5000

# ── TCP behavior ────────────────────────────────────────────
# TCP Fast Open: save 1 RTT on reconnections (client + server)
# Safe on datacenter links; some old middleboxes may not support.
net.ipv4.tcp_fastopen = 3

# Detect dead connections faster (default: 7200s = 2 hours)
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# Close TIME_WAIT faster, reuse sockets
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1

# More ephemeral ports for outbound NAT connections
net.ipv4.ip_local_port_range = 1024 65535

# ── Kernel: crash recovery ──────────────────────────────────
# CRITICAL for remote/datacenter servers.
# Default panic=0 means hang forever — requires manual reboot.
kernel.panic = 10
kernel.panic_on_oops = 1

# ── Kernel: scheduler ──────────────────────────────────────
# Autogroup is a desktop feature that groups processes by TTY.
# On a hypervisor it adds overhead and interferes with vCPU scheduling.
kernel.sched_autogroup_enabled = 0

# ── Virtual memory ──────────────────────────────────────────
# Swappiness: low value keeps VM memory resident.
# Proxmox wiki recommends 10 for ZFS hosts.
vm.swappiness = 10

# Dirty page writeback: flush sooner to avoid large write storms.
# Default 20%/10% means up to 25GB dirty on 128GB host.
# 10%/5% caps at ~12GB dirty — still plenty for NVMe throughput.
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5

# Emergency memory reserve: default ~67MB is too low with 128GB RAM.
# ZFS ARC can consume memory rapidly during scrubs/imports.
# 256MB reserve prevents OOM-killer from targeting VMs.
vm.min_free_kbytes = ${MIN_FREE_KB}

# ── Filesystem ──────────────────────────────────────────────
# Max async I/O requests — needed for many concurrent disk ops
fs.aio-max-nr = 1048576

# Max PIDs — default 32768 is fine for most, but costs nothing to raise
kernel.pid_max = 4194304
SYSCTL

sysctl -p /etc/sysctl.d/90-pve-tune.conf >/dev/null 2>&1
ok "Wrote /etc/sysctl.d/90-pve-tune.conf and applied"

# Verify BBR is active
CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
if [ "$CURRENT_CC" = "bbr" ]; then
    ok "BBR active (was: cubic)"
else
    echo -e "  ${CLR_YELLOW}⚠ Congestion control: ${CURRENT_CC} (BBR may need reboot)${CLR_RESET}"
fi

# ===========================================================
# 3. NIC ring buffer tuning
# ===========================================================
step 3 "NIC ring buffer tuning"

if [ -n "${PHYS_NIC:-}" ]; then
    # Check current and max ring sizes
    RX_MAX=$(ethtool -g "$PHYS_NIC" 2>/dev/null | awk '/^Pre-set/,/^$/{if(/RX:/){print $2; exit}}')
    RX_CUR=$(ethtool -g "$PHYS_NIC" 2>/dev/null | awk '/^Current/,/^$/{if(/RX:/){print $2; exit}}')

    if [ -n "$RX_MAX" ] && [ "$RX_MAX" -gt "${RX_CUR:-0}" ] 2>/dev/null; then
        # Pick target: 1024 or max, whichever is smaller
        TARGET=1024
        [ "$RX_MAX" -lt "$TARGET" ] && TARGET="$RX_MAX"

        if [ "${RX_CUR:-0}" -ge "$TARGET" ]; then
            skip "Ring buffers already ≥${TARGET} (RX: ${RX_CUR}, max: ${RX_MAX})"
        else
            ethtool -G "$PHYS_NIC" rx "$TARGET" tx "$TARGET" 2>/dev/null
            ok "Ring buffers: ${RX_CUR} → ${TARGET} (max: ${RX_MAX})"
        fi

        # Persist via if-up.d hook
        HOOK="/etc/network/if-up.d/nic-tuning"
        cat > "$HOOK" << NICHOOK
#!/bin/sh
# pve-tune.sh — NIC ring buffer tuning
[ "\$IFACE" = "${PHYS_NIC}" ] || exit 0
ethtool -G ${PHYS_NIC} rx ${TARGET} tx ${TARGET} 2>/dev/null
NICHOOK
        chmod +x "$HOOK"
        ok "Persisted in ${HOOK}"
    else
        skip "Ring buffers already at max or ethtool not supported"
    fi
else
    skip "No physical NIC detected"
fi

# ===========================================================
# 4. APT minor optimizations
# ===========================================================
step 4 "APT optimizations"

# Skip translation downloads — saves time on apt update
APT_LANG="/etc/apt/apt.conf.d/99-no-translations"
if [ -f "$APT_LANG" ]; then
    skip "Translation skip already configured"
else
    echo 'Acquire::Languages "none";' > "$APT_LANG"
    ok "Disabled apt translation downloads"
fi

# ===========================================================
# 5. Cleanup legacy / ad-hoc sysctl files
# ===========================================================
step 5 "Cleanup legacy sysctl files"

CLEANED=false

# Remove ad-hoc network tuning file (now consolidated into 90-pve-tune.conf)
if [ -f /etc/sysctl.d/90-network-tuning.conf ]; then
    rm -f /etc/sysctl.d/90-network-tuning.conf
    ok "Removed /etc/sysctl.d/90-network-tuning.conf (consolidated)"
    CLEANED=true
fi

# Remove 99-proxmox.conf if it only has conntrack (duplicate of 99-pve-hardening.conf)
if [ -f /etc/sysctl.d/99-proxmox.conf ]; then
    # Check if it only contains conntrack settings (managed by pve-harden.sh)
    NON_CONNTRACK=$(grep -v '^#' /etc/sysctl.d/99-proxmox.conf | grep -v '^$' | grep -cv 'nf_conntrack' || true)
    if [ "$NON_CONNTRACK" -eq 0 ]; then
        rm -f /etc/sysctl.d/99-proxmox.conf
        ok "Removed /etc/sysctl.d/99-proxmox.conf (conntrack duplicate — managed by pve-harden.sh)"
        CLEANED=true
    else
        echo -e "  ${CLR_YELLOW}⚠ /etc/sysctl.d/99-proxmox.conf has non-conntrack settings — keeping${CLR_RESET}"
    fi
fi

$CLEANED || skip "Nothing to clean up"

# Reload all sysctl to resolve any ordering after cleanup
# Ensure nf_conntrack is loaded first (99-pve-hardening.conf needs it)
modprobe nf_conntrack 2>/dev/null || true
sysctl --system >/dev/null 2>&1

# ===========================================================
# 6. Summary
# ===========================================================
step 6 "Verification"

echo ""
printf "  %-38s %s\n" "TCP congestion:" "$(sysctl -n net.ipv4.tcp_congestion_control)"
printf "  %-38s %s\n" "Qdisc:" "$(sysctl -n net.core.default_qdisc)"
printf "  %-38s %s\n" "Socket buffer max (rmem/wmem):" "$(( $(sysctl -n net.core.rmem_max) / 1048576 ))MB"
printf "  %-38s %s\n" "TCP fastopen:" "$(sysctl -n net.ipv4.tcp_fastopen)"
printf "  %-38s %s\n" "Backlog:" "$(sysctl -n net.core.netdev_max_backlog)"
printf "  %-38s %s\n" "Keepalive:" "$(sysctl -n net.ipv4.tcp_keepalive_time)s / $(sysctl -n net.ipv4.tcp_keepalive_intvl)s / $(sysctl -n net.ipv4.tcp_keepalive_probes) probes"
printf "  %-38s %s\n" "Ephemeral ports:" "$(sysctl -n net.ipv4.ip_local_port_range | tr '\t' '-')"
printf "  %-38s %s\n" "Kernel panic reboot:" "$(sysctl -n kernel.panic)s"
printf "  %-38s %s\n" "Scheduler autogroup:" "$(sysctl -n kernel.sched_autogroup_enabled)"
printf "  %-38s %s\n" "Swappiness:" "$(sysctl -n vm.swappiness)"
printf "  %-38s %s\n" "Dirty ratio/bg:" "$(sysctl -n vm.dirty_ratio)% / $(sysctl -n vm.dirty_background_ratio)%"
printf "  %-38s %s\n" "Min free KB:" "$(sysctl -n vm.min_free_kbytes) ($(( $(sysctl -n vm.min_free_kbytes) / 1024 ))MB)"
if [ -n "${PHYS_NIC:-}" ]; then
    RX_NOW=$(ethtool -g "$PHYS_NIC" 2>/dev/null | awk '/^Current/,/^$/{if(/RX:/){print $2; exit}}')
    printf "  %-38s %s\n" "NIC ring buffers (${PHYS_NIC}):" "RX/TX ${RX_NOW:-unknown}"
fi
echo ""

# List remaining sysctl.d files for visibility
echo -e "${CLR_DIM}  Active sysctl.d files:${CLR_RESET}"
for f in /etc/sysctl.d/*.conf; do
    [ -f "$f" ] && echo -e "${CLR_DIM}    $(basename "$f")${CLR_RESET}"
done

echo ""
echo -e "${CLR_GREEN}═══════════════════════════════════════════════════${CLR_RESET}"
echo -e "${CLR_GREEN} ✓ Performance tuning complete: ${HOST_S}${CLR_RESET}"
echo -e "${CLR_GREEN}═══════════════════════════════════════════════════${CLR_RESET}"
echo -e "${CLR_DIM}All changes are live. No reboot required.${CLR_RESET}"
echo -e "${CLR_DIM}Run on matching host(s) to keep fleet consistent.${CLR_RESET}"
