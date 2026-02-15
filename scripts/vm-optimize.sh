#!/usr/bin/env bash
# vm-optimize.sh — Apply production tunings inside a Proxmox Docker VM
# Designed to be baked into cloud images via virt-customize --run
# Also safe to run standalone: bash vm-optimize.sh
# All changes are idempotent.
set -euo pipefail

G='\033[0;32m'; Y='\033[0;33m'; C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $1"; }
skip() { echo -e "  ${D}⊘${N} $1"; }
step() { echo -e "\n${C}[$1/$TOTAL] $2${N}"; }
TOTAL=8
echo -e "${W}vm-optimize.sh — Production VM tuning${N}"
echo -e "${D}$(date '+%Y-%m-%d %H:%M:%S %Z')${N}"

# ── 1. Sysctl: VM + Network + Filesystem tuning ────────────────────────
step 1 "Sysctl tuning"
SYSCTL_FILE="/etc/sysctl.d/99-vm-optimized.conf"
cat > "$SYSCTL_FILE" <<'SYSCTL'
# vm-optimize.sh — Production sysctl for Docker VMs
# Applied by Proxmox cloud-image template

# ── Virtual Memory ──
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50
vm.overcommit_memory = 1
vm.max_map_count = 1048576
vm.zone_reclaim_mode = 0

# ── Network: TCP performance ──
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1

# ── Network: Buffer sizes ──
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# ── Network: Security ──
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ── Filesystem ──
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 512
fs.aio-max-nr = 1048576

# ── Kernel ──
kernel.panic = 10
kernel.pid_max = 4194304
SYSCTL

# Remove old Docker-specific sysctl if it exists (we replace it)
rm -f /etc/sysctl.d/99-docker-optimized.conf 2>/dev/null || true

sysctl --system &>/dev/null
ok "Wrote $SYSCTL_FILE and applied"

# ── 2. zram swap ────────────────────────────────────────────────────────
step 2 "zram swap (compressed in-RAM swap)"
if swapon --show 2>/dev/null | grep -q zram; then
    skip "zram swap already active"
else
    # Ensure zram module loads on boot
    if ! grep -q '^zram' /etc/modules-load.d/*.conf 2>/dev/null; then
        echo 'zram' > /etc/modules-load.d/zram.conf
    fi
    modprobe zram 2>/dev/null || true

    # Setup script: 25% of RAM, max 4GB, lz4 compression
    cat > /usr/local/sbin/setup-zram.sh <<'ZRAMSCRIPT'
#!/bin/bash
modprobe zram num_devices=1 2>/dev/null || true
MEM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo)
ZRAM_KB=$((MEM_KB / 4))
MAX_KB=$((4 * 1024 * 1024))
[ "$ZRAM_KB" -gt "$MAX_KB" ] && ZRAM_KB=$MAX_KB
echo 1 > /sys/block/zram0/reset 2>/dev/null || true
echo lz4 > /sys/block/zram0/comp_algorithm 2>/dev/null || true
echo "${ZRAM_KB}K" > /sys/block/zram0/disksize
mkswap /dev/zram0 >/dev/null
swapon -p 100 /dev/zram0
ZRAMSCRIPT
    chmod +x /usr/local/sbin/setup-zram.sh

    # Systemd service for boot
    cat > /etc/systemd/system/zram-swap.service <<'ZRAMSVC'
[Unit]
Description=Configure zram swap (25% RAM, lz4)
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/setup-zram.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
ZRAMSVC
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable zram-swap.service &>/dev/null 2>&1 || true

    # Start now if we're in a live system (not virt-customize chroot)
    if [ -d /sys/block/zram0 ] && [ -d /proc/1 ]; then
        /usr/local/sbin/setup-zram.sh 2>/dev/null && ok "zram swap active" || ok "zram configured (activates on boot)"
    else
        ok "zram configured (activates on boot)"
    fi
fi

# ── 3. Docker daemon.json ───────────────────────────────────────────────
step 3 "Docker daemon.json"
DOCKER_JSON="/etc/docker/daemon.json"
if [ -f "$DOCKER_JSON" ] && grep -q '"max-size"' "$DOCKER_JSON" && grep -q '"live-restore"' "$DOCKER_JSON"; then
    skip "daemon.json already configured"
else
    mkdir -p /etc/docker
    cat > "$DOCKER_JSON" <<'DJSON'
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
DJSON
    ok "Wrote $DOCKER_JSON"
fi

# ── 4. Resource limits ──────────────────────────────────────────────────
step 4 "Resource limits (PAM + systemd)"
LIMITS_FILE="/etc/security/limits.d/99-docker.conf"
if [ -f "$LIMITS_FILE" ]; then
    skip "$LIMITS_FILE already exists"
else
    cat > "$LIMITS_FILE" <<'LIMITS'
# vm-optimize.sh — High limits for Docker workloads
*    soft    nofile    1048576
*    hard    nofile    1048576
root soft    nofile    1048576
root hard    nofile    1048576
*    soft    nproc     65535
*    hard    nproc     65535
LIMITS
    ok "Wrote $LIMITS_FILE"
fi

# Systemd default limits
SYSTEMD_CONF="/etc/systemd/system.conf.d/limits.conf"
if [ -f "$SYSTEMD_CONF" ]; then
    skip "$SYSTEMD_CONF already exists"
else
    mkdir -p /etc/systemd/system.conf.d
    cat > "$SYSTEMD_CONF" <<'SYSD'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=65535
SYSD
    ok "Wrote $SYSTEMD_CONF"
fi

# ── 5. BBR module loading ──────────────────────────────────────────────
step 5 "TCP BBR module"
if lsmod 2>/dev/null | grep -q tcp_bbr; then
    skip "tcp_bbr already loaded"
else
    modprobe tcp_bbr 2>/dev/null || true
    if ! grep -q '^tcp_bbr' /etc/modules-load.d/*.conf 2>/dev/null; then
        echo 'tcp_bbr' > /etc/modules-load.d/tcp-bbr.conf
    fi
    ok "tcp_bbr module loaded + persisted"
fi

# ── 6. fstrim timer ────────────────────────────────────────────────────
step 6 "fstrim timer (SSD TRIM)"
if systemctl is-enabled fstrim.timer &>/dev/null 2>&1; then
    skip "fstrim.timer already enabled"
else
    systemctl enable fstrim.timer &>/dev/null 2>&1 || true
    ok "fstrim.timer enabled"
fi

# ── 7. Disable coredumps (save disk space) ─────────────────────────────
step 7 "Coredump limits"
CORE_CONF="/etc/security/limits.d/10-coredump-debian.conf"
if [ -f "$CORE_CONF" ]; then
    skip "Coredump limits already configured"
else
    cat > "$CORE_CONF" <<'CORE'
*    soft    core    0
root soft    core    0
*    hard    core    infinity
root hard    core    infinity
CORE
    ok "Coredump soft limit set to 0"
fi

# ── 8. Cleanup ─────────────────────────────────────────────────────────
step 8 "Final cleanup"
# Remove old sysctl that we replaced
for OLD in /etc/sysctl.d/99-docker-optimized.conf /etc/systemd/zram-generator.conf; do
    [ -f "$OLD" ] && { rm -f "$OLD"; ok "Removed stale $OLD"; }
done

# Truncate machine-id for template cloning
if [ "${TEMPLATE_MODE:-}" = "1" ]; then
    truncate -s 0 /etc/machine-id 2>/dev/null || true
    rm -f /var/lib/dbus/machine-id 2>/dev/null || true
    ok "Truncated machine-id for template"
fi

# Re-apply sysctl to catch any module-dependent settings (BBR)
sysctl --system &>/dev/null 2>&1 || true

echo ""
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo -e "${G} ✓ All optimizations applied${N}"
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo -e "${D}Changes take effect immediately. zram swap active on next boot.${N}"
echo -e "${D}Run vm-audit.sh to verify.${N}"
