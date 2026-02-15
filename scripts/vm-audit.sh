#!/usr/bin/env bash
# vm-audit.sh — Comprehensive VM system audit & benchmark
# Run inside a Proxmox VM to check configs, optimizations, and performance
# Usage: bash vm-audit.sh [--bench]   (--bench runs I/O and CPU benchmarks)
set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[0;34m'
C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'

RUN_BENCH=false
[[ "${1:-}" == "--bench" ]] && RUN_BENCH=true

# ── Helpers ─────────────────────────────────────────────────────────────
section()  { echo -e "\n${W}═══════════════════════════════════════════════════${N}"; echo -e "${W} $1${N}"; echo -e "${W}═══════════════════════════════════════════════════${N}"; }
subsect()  { echo -e "\n${C}─── $1 ───${N}"; }
ok()       { echo -e "  ${G}✓${N} $1"; }
warn()     { echo -e "  ${Y}⚠${N} $1"; }
bad()      { echo -e "  ${R}✗${N} $1"; }
info()     { echo -e "  ${D}·${N} $1"; }
val()      { printf "  ${B}%-32s${N} %s\n" "$1" "$2"; }
sysval()   { local v; v=$(cat "$1" 2>/dev/null || echo "N/A"); printf "  ${B}%-32s${N} %s" "$2" "$v"; if [ -n "${3:-}" ]; then if [ "$v" = "$3" ]; then echo -e " ${G}✓${N}"; else echo -e " ${Y}(recommended: $3)${N}"; fi; else echo; fi; }

check_sysctl() {
    local key="$1" recommended="${2:-}" label="${3:-$1}"
    local current
    current=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if [ -n "$recommended" ]; then
        if [ "$current" = "$recommended" ]; then
            printf "  ${G}✓${N} ${B}%-42s${N} = %s\n" "$label" "$current"
        else
            printf "  ${Y}⚠${N} ${B}%-42s${N} = %s ${Y}(want: %s)${N}\n" "$label" "$current" "$recommended"
        fi
    else
        printf "  ${D}·${N} ${B}%-42s${N} = %s\n" "$label" "$current"
    fi
}

# ════════════════════════════════════════════════════════════════════════
section "1. SYSTEM IDENTITY"
# ════════════════════════════════════════════════════════════════════════
val "Hostname"          "$(hostname)"
val "OS"                "$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s)"
val "Kernel"            "$(uname -r)"
val "Arch"              "$(uname -m)"
val "Uptime"            "$(uptime -p 2>/dev/null || uptime)"
val "Date/TZ"           "$(date '+%Y-%m-%d %H:%M:%S %Z')"

subsect "Virtualization"
val "Hypervisor"        "$(systemd-detect-virt 2>/dev/null || echo 'unknown')"
val "Machine type"      "$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo 'unknown')"
val "BIOS vendor"       "$(cat /sys/class/dmi/id/bios_vendor 2>/dev/null || echo 'unknown')"
val "Board"             "$(cat /sys/class/dmi/id/board_name 2>/dev/null || echo 'unknown')"

# QEMU guest agent
if systemctl is-active --quiet qemu-guest-agent 2>/dev/null; then
    ok "qemu-guest-agent: active"
else
    bad "qemu-guest-agent: not running"
fi

# ════════════════════════════════════════════════════════════════════════
section "2. CPU"
# ════════════════════════════════════════════════════════════════════════
val "Model"             "$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
val "Cores (vCPU)"      "$(nproc)"
val "Threads/core"      "$(lscpu | awk '/Thread\(s\) per core/{print $NF}')"
val "Sockets"           "$(lscpu | awk '/Socket\(s\)/{print $NF}')"
val "MHz (current)"     "$(lscpu | awk '/CPU MHz/{print $NF}' | head -1)"
val "CPU flags"         "$(grep -m1 -oP '(svm|vmx|aes|avx2?|sse4_[12]|rdrand|sha_ni)' /proc/cpuinfo | tr '\n' ' ' || echo 'N/A')"

subsect "CPU Governor & Frequency"
if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    val "Governor"      "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
    val "Min freq"      "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq 2>/dev/null || echo N/A) kHz"
    val "Max freq"      "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null || echo N/A) kHz"
else
    info "No cpufreq (host governor applies via KVM passthrough)"
fi

subsect "CPU Vulnerability Mitigations"
if [ -d /sys/devices/system/cpu/vulnerabilities ]; then
    for vuln in /sys/devices/system/cpu/vulnerabilities/*; do
        name=$(basename "$vuln")
        status=$(cat "$vuln" 2>/dev/null)
        case "$status" in
            *"Not affected"*|*"Mitigation"*) printf "  ${G}✓${N} %-22s %s\n" "$name" "$status" ;;
            *"Vulnerable"*)                  printf "  ${R}✗${N} %-22s %s\n" "$name" "$status" ;;
            *)                               printf "  ${D}·${N} %-22s %s\n" "$name" "$status" ;;
        esac
    done
fi

# ════════════════════════════════════════════════════════════════════════
section "3. MEMORY & SWAP"
# ════════════════════════════════════════════════════════════════════════
MEM_TOTAL_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo)
MEM_TOTAL_MB=$((MEM_TOTAL_KB / 1024))
MEM_AVAIL_KB=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
MEM_AVAIL_MB=$((MEM_AVAIL_KB / 1024))
SWAP_TOTAL_KB=$(awk '/SwapTotal/{print $2}' /proc/meminfo)
SWAP_TOTAL_MB=$((SWAP_TOTAL_KB / 1024))

val "Total RAM"         "${MEM_TOTAL_MB} MB"
val "Available"         "${MEM_AVAIL_MB} MB ($(( MEM_AVAIL_KB * 100 / MEM_TOTAL_KB ))% free)"
val "Buffers+Cached"    "$(awk '/^Buffers/{b=$2} /^Cached:/{c=$2} END{printf "%d MB", (b+c)/1024}' /proc/meminfo)"
val "Swap total"        "${SWAP_TOTAL_MB} MB"
val "Swap used"         "$(awk '/SwapFree/{printf "%d MB", ('$SWAP_TOTAL_KB'-$2)/1024}' /proc/meminfo)"

if [ "$SWAP_TOTAL_KB" -eq 0 ]; then
    warn "No swap configured (risky for Docker workloads — OOM killer will be aggressive)"
else
    ok "Swap present: ${SWAP_TOTAL_MB} MB"
fi

subsect "Balloon Driver"
if lsmod 2>/dev/null | grep -q virtio_balloon; then
    ok "virtio_balloon loaded"
    if [ -f /sys/devices/system/memory/auto_online_blocks ]; then
        val "Memory auto-online"  "$(cat /sys/devices/system/memory/auto_online_blocks)"
    fi
else
    info "No balloon driver (fixed RAM allocation)"
fi

subsect "Hugepages"
HP_TOTAL=$(awk '/HugePages_Total/{print $2}' /proc/meminfo)
HP_FREE=$(awk '/HugePages_Free/{print $2}' /proc/meminfo)
HP_SIZE=$(awk '/Hugepagesize/{print $2}' /proc/meminfo)
THP=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo "N/A")

val "HugePages total"   "$HP_TOTAL"
val "HugePages free"    "$HP_FREE"
val "Hugepage size"     "${HP_SIZE} kB"
val "Transparent HP"    "$THP"

if echo "$THP" | grep -q '\[always\]'; then
    ok "THP=always (good default for general workloads)"
elif echo "$THP" | grep -q '\[madvise\]'; then
    ok "THP=madvise (good for databases)"
elif echo "$THP" | grep -q '\[never\]'; then
    warn "THP=never (consider madvise for Docker workloads)"
fi

subsect "OOM Configuration"
val "vm.oom_kill_allocating_task" "$(sysctl -n vm.oom_kill_allocating_task 2>/dev/null)"
val "vm.panic_on_oom"            "$(sysctl -n vm.panic_on_oom 2>/dev/null)"
val "vm.overcommit_memory"       "$(sysctl -n vm.overcommit_memory 2>/dev/null)"
val "vm.overcommit_ratio"        "$(sysctl -n vm.overcommit_ratio 2>/dev/null)"

# ════════════════════════════════════════════════════════════════════════
section "4. SYSCTL TUNING"
# ════════════════════════════════════════════════════════════════════════
subsect "Virtual Memory"
check_sysctl vm.swappiness              "10"
check_sysctl vm.dirty_ratio             "15"
check_sysctl vm.dirty_background_ratio  "5"
check_sysctl vm.vfs_cache_pressure      "50"
check_sysctl vm.min_free_kbytes         ""
check_sysctl vm.zone_reclaim_mode       "0"
check_sysctl vm.max_map_count           "262144"    "vm.max_map_count (ES/Docker needs ≥262144)"

subsect "Network — Core"
check_sysctl net.core.somaxconn                 "65535"
check_sysctl net.core.netdev_max_backlog        "65535"
check_sysctl net.core.rmem_max                  "16777216"
check_sysctl net.core.wmem_max                  "16777216"
check_sysctl net.core.rmem_default              ""
check_sysctl net.core.wmem_default              ""
check_sysctl net.core.optmem_max                ""

subsect "Network — TCP"
check_sysctl net.ipv4.tcp_max_syn_backlog       "65535"
check_sysctl net.ipv4.tcp_fin_timeout           "15"
check_sysctl net.ipv4.tcp_tw_reuse              "1"
check_sysctl net.ipv4.tcp_keepalive_time        "300"
check_sysctl net.ipv4.tcp_keepalive_intvl       "30"
check_sysctl net.ipv4.tcp_keepalive_probes      "5"
check_sysctl net.ipv4.tcp_slow_start_after_idle "0"
check_sysctl net.ipv4.tcp_mtu_probing           "1"
check_sysctl net.ipv4.tcp_syncookies            "1"

TCP_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
if [ "$TCP_CC" = "bbr" ]; then
    ok "TCP congestion: bbr"
else
    warn "TCP congestion: $TCP_CC (bbr recommended)"
fi

QDISC=$(sysctl -n net.core.default_qdisc 2>/dev/null)
if [ "$QDISC" = "fq" ]; then
    ok "Queue discipline: fq"
else
    warn "Queue discipline: $QDISC (fq recommended for bbr)"
fi

subsect "Network — TCP Memory (bytes)"
check_sysctl net.ipv4.tcp_rmem ""
check_sysctl net.ipv4.tcp_wmem ""

subsect "Network — Security"
check_sysctl net.ipv4.conf.all.rp_filter        "1"
check_sysctl net.ipv4.conf.default.rp_filter     "1"
check_sysctl net.ipv4.icmp_echo_ignore_broadcasts "1"
check_sysctl net.ipv4.conf.all.accept_redirects   "0"
check_sysctl net.ipv4.conf.all.send_redirects      "0"

subsect "Network — IPv6"
check_sysctl net.ipv6.conf.all.disable_ipv6 ""
check_sysctl net.ipv6.conf.all.forwarding   ""

subsect "Filesystem"
check_sysctl fs.file-max           ""
check_sysctl fs.inotify.max_user_watches   "524288"  "fs.inotify.max_user_watches (Docker/Node needs ≥524288)"
check_sysctl fs.inotify.max_user_instances ""
check_sysctl fs.aio-max-nr        ""

# ════════════════════════════════════════════════════════════════════════
section "5. DISK & I/O"
# ════════════════════════════════════════════════════════════════════════
echo -e "  ${D}Device           Size   RO  Sched      FS       Mount${N}"
lsblk -ndo NAME,SIZE,RO,MODEL 2>/dev/null | while read -r name size ro model; do
    sched=$(cat "/sys/block/$name/queue/scheduler" 2>/dev/null | tr -d '[]' | awk '{for(i=1;i<=NF;i++) if($i ~ /^\[?[a-z]/) print $i}')
    sched_raw=$(cat "/sys/block/$name/queue/scheduler" 2>/dev/null || echo "?")
    rota=$(cat "/sys/block/$name/queue/rotational" 2>/dev/null || echo "?")
    # Find mount + FS
    mp=$(lsblk -nro MOUNTPOINT "/dev/$name" 2>/dev/null | grep -v '^$' | head -1)
    fs=$(lsblk -nro FSTYPE "/dev/$name" 2>/dev/null | grep -v '^$' | head -1)
    [ -z "$mp" ] && { mp=$(lsblk -nro MOUNTPOINT "/dev/${name}"* 2>/dev/null | grep -v '^$' | head -1); fs=$(lsblk -nro FSTYPE "/dev/${name}"* 2>/dev/null | grep -v '^$' | head -1); }
    printf "  %-16s %-6s %-3s %-10s %-8s %s\n" "$name" "$size" "rota=$rota" "$sched_raw" "${fs:-—}" "${mp:-—}"
done

subsect "Disk Queue Parameters"
for disk in /sys/block/sd* /sys/block/vd* /sys/block/nvme* 2>/dev/null; do
    [ -d "$disk" ] || continue
    name=$(basename "$disk")
    val "$name scheduler"    "$(cat "$disk/queue/scheduler" 2>/dev/null)"
    val "$name nr_requests"  "$(cat "$disk/queue/nr_requests" 2>/dev/null)"
    val "$name read_ahead_kb" "$(cat "$disk/queue/read_ahead_kb" 2>/dev/null)"
    val "$name rotational"   "$(cat "$disk/queue/rotational" 2>/dev/null)"
    val "$name discard_max"  "$(cat "$disk/queue/discard_max_bytes" 2>/dev/null)"
done

subsect "Filesystem Usage"
df -hT -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | head -10

subsect "Mount Options"
mount | grep -E '^/dev/' | while read -r line; do
    dev=$(echo "$line" | awk '{print $1}')
    mp=$(echo "$line" | awk '{print $3}')
    fs=$(echo "$line" | awk '{print $5}')
    opts=$(echo "$line" | grep -oP '\(.*\)')
    printf "  %-12s %-8s %-8s %s\n" "$dev" "$mp" "$fs" "$opts"
done

subsect "TRIM / Discard"
if command -v fstrim &>/dev/null; then
    # Check fstrim timer
    if systemctl is-enabled fstrim.timer &>/dev/null; then
        ok "fstrim.timer: $(systemctl is-enabled fstrim.timer 2>/dev/null)"
    else
        warn "fstrim.timer not enabled (enable for SSD TRIM)"
    fi
fi

# ════════════════════════════════════════════════════════════════════════
section "6. NETWORK INTERFACES"
# ════════════════════════════════════════════════════════════════════════
ip -4 addr show | awk '/^[0-9]+:/{iface=$2} /inet /{print "  " iface " " $2}'
echo ""
# Default route
val "Default gateway"    "$(ip route show default 2>/dev/null | awk '{print $3, "via", $5}')"
val "DNS"               "$(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{printf "%s ", $2}')"

subsect "Interface Details"
for iface in $(ls /sys/class/net/ | grep -v lo); do
    driver=$(readlink "/sys/class/net/$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || echo "?")
    speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo "?")
    mtu=$(cat "/sys/class/net/$iface/mtu" 2>/dev/null || echo "?")
    tx_qlen=$(cat "/sys/class/net/$iface/tx_queue_len" 2>/dev/null || echo "?")
    printf "  ${B}%-10s${N} driver=%-12s speed=%-8s mtu=%-6s txqlen=%s\n" "$iface" "$driver" "${speed}Mbps" "$mtu" "$tx_qlen"
done

# ════════════════════════════════════════════════════════════════════════
section "7. DOCKER"
# ════════════════════════════════════════════════════════════════════════
if command -v docker &>/dev/null; then
    val "Docker version"     "$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')"
    val "Compose version"    "$(docker compose version 2>/dev/null | awk '{print $NF}')"
    val "Storage driver"     "$(docker info 2>/dev/null | awk '/Storage Driver/{print $NF}')"
    val "Cgroup driver"      "$(docker info 2>/dev/null | awk '/Cgroup Driver/{print $NF}')"
    val "Logging driver"     "$(docker info 2>/dev/null | awk '/Logging Driver/{print $NF}')"
    val "Runtime"            "$(docker info 2>/dev/null | awk '/Default Runtime/{print $NF}')"
    val "Containers"         "$(docker info 2>/dev/null | awk '/Containers:/{print $NF}')"
    val "Images"             "$(docker info 2>/dev/null | awk '/Images:/{print $NF}')"

    if systemctl is-active --quiet docker; then
        ok "Docker daemon: running"
    else
        bad "Docker daemon: not running"
    fi

    # Docker daemon.json
    if [ -f /etc/docker/daemon.json ]; then
        subsect "daemon.json"
        cat /etc/docker/daemon.json 2>/dev/null
    else
        info "No /etc/docker/daemon.json (using defaults)"
    fi

    # Check Docker log rotation
    LOG_DRIVER=$(docker info 2>/dev/null | awk '/Logging Driver/{print $NF}')
    if [ "$LOG_DRIVER" = "json-file" ]; then
        warn "Docker logging: json-file without size limits — logs can fill disk"
        info "Recommend: add log-opts in daemon.json: max-size=10m, max-file=3"
    fi
else
    bad "Docker not installed"
fi

# ════════════════════════════════════════════════════════════════════════
section "8. SECURITY & HARDENING"
# ════════════════════════════════════════════════════════════════════════
subsect "SSH"
if [ -f /etc/ssh/sshd_config ]; then
    SSHD_PORT=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    ROOT_LOGIN=$(grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    PASS_AUTH=$(grep -E '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    val "SSH port"                "${SSHD_PORT:-22}"
    val "PermitRootLogin"         "${ROOT_LOGIN:-(default)}"
    val "PasswordAuthentication"  "${PASS_AUTH:-(default)}"
fi

subsect "Firewall"
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
    ok "UFW: active"
    ufw status numbered 2>/dev/null | head -15
elif command -v iptables &>/dev/null; then
    INPUT_RULES=$(iptables -L INPUT --line-numbers 2>/dev/null | wc -l)
    val "iptables INPUT rules" "$((INPUT_RULES - 2))"
    if command -v nft &>/dev/null; then
        NFT_RULES=$(nft list ruleset 2>/dev/null | wc -l)
        val "nftables rules" "$NFT_RULES"
    fi
else
    warn "No firewall detected"
fi

subsect "AppArmor / SELinux"
if command -v aa-status &>/dev/null; then
    AA=$(aa-status --enabled 2>/dev/null && echo "enabled" || echo "disabled")
    val "AppArmor" "$AA"
elif command -v getenforce &>/dev/null; then
    val "SELinux" "$(getenforce 2>/dev/null)"
else
    info "No MAC framework (AppArmor/SELinux)"
fi

subsect "Automatic Updates"
if systemctl is-enabled unattended-upgrades.service &>/dev/null 2>&1; then
    ok "unattended-upgrades: enabled"
else
    warn "unattended-upgrades: not enabled"
fi

# ════════════════════════════════════════════════════════════════════════
section "9. RESOURCE LIMITS"
# ════════════════════════════════════════════════════════════════════════
subsect "System Limits"
val "fs.file-max"        "$(sysctl -n fs.file-max 2>/dev/null)"
val "Open files (soft)"  "$(ulimit -Sn 2>/dev/null)"
val "Open files (hard)"  "$(ulimit -Hn 2>/dev/null)"
val "Max user processes"  "$(ulimit -Su 2>/dev/null)"
val "Max locked memory"   "$(ulimit -Sl 2>/dev/null) kB"

subsect "Limits.conf (non-default entries)"
if [ -f /etc/security/limits.conf ]; then
    grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -v '^$' | while read -r line; do
        info "$line"
    done
    LIMITS_COUNT=$(grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -v '^$' | wc -l)
    [ "$LIMITS_COUNT" -eq 0 ] && info "(empty — using defaults)"
fi

# Check limits.d
if [ -d /etc/security/limits.d ] && ls /etc/security/limits.d/*.conf &>/dev/null 2>&1; then
    for f in /etc/security/limits.d/*.conf; do
        info "$(basename "$f"):"
        grep -v '^#' "$f" | grep -v '^$' | while read -r line; do
            info "  $line"
        done
    done
fi

subsect "Systemd Default Limits"
val "DefaultLimitNOFILE"  "$(systemctl show --property=DefaultLimitNOFILE 2>/dev/null | cut -d= -f2)"
val "DefaultLimitNPROC"   "$(systemctl show --property=DefaultLimitNPROC 2>/dev/null | cut -d= -f2)"

# ════════════════════════════════════════════════════════════════════════
section "10. SERVICES & BOOT"
# ════════════════════════════════════════════════════════════════════════
subsect "Enabled Services (non-default)"
systemctl list-unit-files --type=service --state=enabled 2>/dev/null | \
    grep -v '@\|dbus\|systemd\|getty\|networking\|ssh\|cron\|rsyslog\|logrotate\|cloud-' | \
    grep enabled | while read -r svc state _; do
    info "$svc"
done

subsect "Failed Services"
FAILED=$(systemctl --failed --no-pager 2>/dev/null | grep -c 'failed' || echo 0)
if [ "$FAILED" -gt 0 ]; then
    bad "$FAILED failed service(s):"
    systemctl --failed --no-pager 2>/dev/null | grep 'failed'
else
    ok "No failed services"
fi

subsect "Boot Performance"
if command -v systemd-analyze &>/dev/null; then
    val "Boot time" "$(systemd-analyze 2>/dev/null | head -1)"
    echo -e "  ${D}Slowest units:${N}"
    systemd-analyze blame 2>/dev/null | head -5 | while read -r line; do
        info "$line"
    done
fi

# ════════════════════════════════════════════════════════════════════════
section "11. CLOUD-INIT"
# ════════════════════════════════════════════════════════════════════════
if command -v cloud-init &>/dev/null; then
    val "Cloud-init version" "$(cloud-init --version 2>&1 | awk '{print $NF}')"
    CI_STATUS=$(cloud-init status 2>/dev/null | awk '{print $NF}')
    if [ "$CI_STATUS" = "done" ]; then
        ok "Status: done"
    else
        warn "Status: $CI_STATUS"
    fi
    val "Datasource" "$(cloud-init query ds 2>/dev/null | head -1 || echo 'N/A')"
else
    info "cloud-init not installed"
fi

# ════════════════════════════════════════════════════════════════════════
section "12. ENTROPY & RANDOM"
# ════════════════════════════════════════════════════════════════════════
val "Available entropy"  "$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null) bits"
val "Pool size"          "$(cat /proc/sys/kernel/random/poolsize 2>/dev/null) bits"
if [ "$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null)" -lt 256 ] 2>/dev/null; then
    warn "Low entropy — consider installing haveged or rng-tools"
else
    ok "Entropy sufficient"
fi
if lsmod 2>/dev/null | grep -q virtio_rng; then
    ok "virtio-rng: loaded (hardware RNG from host)"
else
    info "virtio-rng not loaded"
fi

# ════════════════════════════════════════════════════════════════════════
section "13. SYSCTL DUMP (all non-default)"
# ════════════════════════════════════════════════════════════════════════
subsect "Custom sysctl files"
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    CONTENT=$(grep -v '^#' "$f" | grep -v '^$')
    if [ -n "$CONTENT" ]; then
        echo -e "  ${C}$f${N}"
        echo "$CONTENT" | while read -r line; do info "$line"; done
    fi
done

# ════════════════════════════════════════════════════════════════════════
section "14. SUMMARY & RECOMMENDATIONS"
# ════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${W}Checking for common optimizations...${N}"
echo ""

# Collect recommendations
RECS=()

# Swap
[ "$SWAP_TOTAL_KB" -eq 0 ] && RECS+=("Create swap (1-2GB) or enable zram for OOM protection")

# Swappiness
SW=$(sysctl -n vm.swappiness 2>/dev/null)
[ "$SW" -gt 30 ] 2>/dev/null && RECS+=("Lower vm.swappiness to 10 (current: $SW)")

# BBR
[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" != "bbr" ] && RECS+=("Enable TCP BBR: net.ipv4.tcp_congestion_control=bbr")

# somaxconn
[ "$(sysctl -n net.core.somaxconn 2>/dev/null)" -lt 4096 ] 2>/dev/null && RECS+=("Increase net.core.somaxconn (current: $(sysctl -n net.core.somaxconn), want: 65535)")

# file-max / inotify
[ "$(sysctl -n fs.inotify.max_user_watches 2>/dev/null)" -lt 524288 ] 2>/dev/null && RECS+=("Increase fs.inotify.max_user_watches to 524288")

# max_map_count (Elasticsearch / Java)
[ "$(sysctl -n vm.max_map_count 2>/dev/null)" -lt 262144 ] 2>/dev/null && RECS+=("Increase vm.max_map_count to 262144")

# Docker log rotation
if command -v docker &>/dev/null; then
    LD=$(docker info 2>/dev/null | awk '/Logging Driver/{print $NF}')
    if [ "$LD" = "json-file" ] && [ ! -f /etc/docker/daemon.json ]; then
        RECS+=("Configure Docker log rotation in /etc/docker/daemon.json")
    fi
fi

# fstrim
if ! systemctl is-enabled fstrim.timer &>/dev/null 2>&1; then
    RECS+=("Enable fstrim.timer for SSD TRIM support")
fi

# THP
THP_CUR=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)
echo "$THP_CUR" | grep -q '\[never\]' && RECS+=("Set THP to madvise: echo madvise > /sys/kernel/mm/transparent_hugepage/enabled")

# Dirty ratios
DR=$(sysctl -n vm.dirty_ratio 2>/dev/null)
[ "$DR" -gt 20 ] 2>/dev/null && RECS+=("Lower vm.dirty_ratio to 15 (current: $DR)")

# Print recommendations
if [ ${#RECS[@]} -eq 0 ]; then
    ok "No critical optimizations needed"
else
    echo -e "  ${Y}Found ${#RECS[@]} recommendation(s):${N}"
    for i in "${!RECS[@]}"; do
        echo -e "  ${Y}$((i+1)).${N} ${RECS[$i]}"
    done
fi

# ════════════════════════════════════════════════════════════════════════
# BENCHMARKS (only with --bench flag)
# ════════════════════════════════════════════════════════════════════════
if $RUN_BENCH; then

section "B1. CPU BENCHMARK"
# Quick CPU test with dd + openssl (always available)
subsect "Single-core: SHA256 hashing (10s)"
HASH_OPS=$(timeout 10 openssl speed -seconds 10 sha256 2>/dev/null | awk '/sha256/{print $NF}')
val "SHA256 throughput" "${HASH_OPS:-N/A}"

# dd-based CPU: compress /dev/zero
subsect "Single-core: gzip compress (256MB /dev/zero)"
CPU_START=$(date +%s%N)
dd if=/dev/zero bs=1M count=256 2>/dev/null | gzip > /dev/null
CPU_END=$(date +%s%N)
CPU_MS=$(( (CPU_END - CPU_START) / 1000000 ))
val "gzip 256MB" "${CPU_MS} ms"

if command -v sysbench &>/dev/null; then
    subsect "sysbench cpu (single-thread, 10s)"
    EVENTS=$(sysbench cpu --cpu-max-prime=20000 --threads=1 --time=10 run 2>/dev/null | awk '/total number of events/{print $NF}')
    val "Events/10s (1T)" "$EVENTS"

    CORES=$(nproc)
    subsect "sysbench cpu (all ${CORES} threads, 10s)"
    EVENTS_MT=$(sysbench cpu --cpu-max-prime=20000 --threads=$CORES --time=10 run 2>/dev/null | awk '/total number of events/{print $NF}')
    val "Events/10s (${CORES}T)" "$EVENTS_MT"
else
    warn "sysbench not installed — install with: apt install sysbench"
fi

section "B2. MEMORY BENCHMARK"
subsect "dd memory bandwidth (1GB)"
MEM_RESULT=$(dd if=/dev/zero of=/dev/null bs=1M count=1024 2>&1 | tail -1)
val "Memory bandwidth" "$(echo "$MEM_RESULT" | grep -oP '[0-9.]+ [GM]B/s' || echo "$MEM_RESULT")"

if command -v sysbench &>/dev/null; then
    subsect "sysbench memory (sequential write, 10s)"
    MEM_OPS=$(sysbench memory --memory-block-size=1M --memory-total-size=100G --memory-oper=write --threads=1 --time=10 run 2>/dev/null | awk '/transferred/{print $0}')
    val "Memory write" "$MEM_OPS"
fi

section "B3. DISK I/O BENCHMARK"
BENCH_DIR="/tmp/bench_$$"
mkdir -p "$BENCH_DIR"

subsect "Sequential write (1GB, direct I/O)"
WRITE_RESULT=$(dd if=/dev/zero of="${BENCH_DIR}/testfile" bs=1M count=1024 conv=fdatasync oflag=direct 2>&1 | tail -1)
val "Seq write" "$(echo "$WRITE_RESULT" | grep -oP '[0-9.]+ [GM]B/s' || echo "$WRITE_RESULT")"

subsect "Sequential read (1GB, direct I/O)"
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
READ_RESULT=$(dd if="${BENCH_DIR}/testfile" of=/dev/null bs=1M count=1024 iflag=direct 2>&1 | tail -1)
val "Seq read" "$(echo "$READ_RESULT" | grep -oP '[0-9.]+ [GM]B/s' || echo "$READ_RESULT")"

subsect "Random 4K write (fdatasync, IOPS)"
RAND_RESULT=$(dd if=/dev/zero of="${BENCH_DIR}/4ktest" bs=4k count=10000 conv=fdatasync oflag=direct 2>&1 | tail -1)
val "4K write" "$(echo "$RAND_RESULT" | grep -oP '[0-9.]+ [kMG]B/s' || echo "$RAND_RESULT")"

if command -v sysbench &>/dev/null; then
    subsect "sysbench fileio (random r/w, 10s)"
    sysbench fileio --file-total-size=512M prepare --file-test-mode=rndrw &>/dev/null
    FIO_RESULT=$(sysbench fileio --file-total-size=512M --file-test-mode=rndrw --time=10 --file-extra-flags=direct run 2>/dev/null)
    FIO_READ=$(echo "$FIO_RESULT" | awk '/read, MiB/{print $0}')
    FIO_WRITE=$(echo "$FIO_RESULT" | awk '/written, MiB/{print $0}')
    FIO_IOPS=$(echo "$FIO_RESULT" | awk '/IOPS/{print $0}' | tail -1)
    val "Random read"  "$FIO_READ"
    val "Random write" "$FIO_WRITE"
    val "IOPS"         "$FIO_IOPS"
    sysbench fileio --file-total-size=512M cleanup &>/dev/null
fi

rm -rf "$BENCH_DIR"

section "B4. NETWORK BENCHMARK"
subsect "Download speed (Hetzner mirror)"
DL_RESULT=$(curl -so /dev/null -w '%{speed_download}' --connect-timeout 5 --max-time 15 http://speed.hetzner.de/100MB.bin 2>/dev/null || echo "0")
DL_MBPS=$(echo "$DL_RESULT" | awk '{printf "%.1f MB/s (%.0f Mbit/s)", $1/1048576, $1*8/1048576}')
val "Download" "$DL_MBPS"

subsect "Latency"
for target in 1.1.1.1 8.8.8.8 speed.hetzner.de; do
    RTT=$(ping -c3 -W2 "$target" 2>/dev/null | awk -F/ '/avg/{print $5 " ms"}')
    val "Ping $target" "${RTT:-timeout}"
done

else
    echo ""
    echo -e "${D}Benchmarks skipped. Run with --bench flag to include performance tests.${N}"
fi

# ════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo -e "${W} Audit complete: $(date '+%Y-%m-%d %H:%M:%S %Z')${N}"
echo -e "${W}═══════════════════════════════════════════════════${N}"
