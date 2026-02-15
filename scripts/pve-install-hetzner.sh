#!/usr/bin/bash
# pve-install-hetzner.sh — Automated Proxmox VE installer for Hetzner dedicated servers
# Based on: https://github.com/ariadata/proxmox-hetzner (MIT License)
# Modified: Non-interactive mode with TOML config, improved error handling
#
# Usage:
#   Interactive:     bash pve-install-hetzner.sh
#   Non-interactive: bash pve-install-hetzner.sh --config server.toml
#   Dry-run:         bash pve-install-hetzner.sh --config server.toml --dry-run
#   Curl one-liner:  bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-install-hetzner.sh)
#   Curl + config:   bash <(curl -sSL .../pve-install-hetzner.sh) --config-url https://your-host.com/myserver.toml
#
# Run from Hetzner Rescue System (Linux 64-bit)
# Repo: https://github.com/yurrosh/proxmox-utils-hetzner

set -euo pipefail
cd /root

# ---- Colors ----
CLR_RED="\033[1;31m"
CLR_GREEN="\033[1;32m"
CLR_YELLOW="\033[1;33m"
CLR_BLUE="\033[1;34m"
CLR_CYAN="\033[1;36m"
CLR_DIM="\033[2m"
CLR_RESET="\033[m"

log_info()  { echo -e "${CLR_BLUE}[INFO]  $*${CLR_RESET}"; }
log_ok()    { echo -e "${CLR_GREEN}[OK]    $*${CLR_RESET}"; }
log_warn()  { echo -e "${CLR_YELLOW}[WARN]  $*${CLR_RESET}"; }
log_err()   { echo -e "${CLR_RED}[ERROR] $*${CLR_RESET}"; }
log_step()  { echo -e "\n${CLR_CYAN}═══ $* ═══${CLR_RESET}"; }
log_debug() { echo -e "${CLR_DIM}[DEBUG] $*${CLR_RESET}"; }
log_cmd()   { echo -e "${CLR_DIM}  \$ $*${CLR_RESET}"; }

die() { log_err "$@"; exit 1; }

# ---- Error trap — shows line number on unexpected exit ----
trap 'log_err "Script failed at line $LINENO (exit code $?). Last command: $BASH_COMMAND"' ERR

# ---- Ensure root ----
if [[ $EUID -ne 0 ]]; then die "Must run as root"; fi

# ---- Detect terminal for interactive prompts ----
# bash <(curl ...) keeps stdin on terminal; curl|bash redirects stdin to pipe
if [[ -c /dev/tty ]]; then
    TTY_INPUT="/dev/tty"
elif [[ -t 0 ]]; then
    TTY_INPUT="/dev/stdin"
else
    TTY_INPUT=""
fi
log_debug "TTY_INPUT=${TTY_INPUT:-none}, shell=$BASH_VERSION, PID=$$"

SCRIPT_START=$(date +%s)

# ---- Parse arguments ----
CONFIG_FILE=""
CONFIG_URL=""
DRY_RUN=false
SKIP_REBOOT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config|-c)     CONFIG_FILE="$2"; shift 2 ;;
        --config-url|-u) CONFIG_URL="$2"; shift 2 ;;
        --dry-run|-n)    DRY_RUN=true; shift ;;
        --no-reboot)     SKIP_REBOOT=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--config <file.toml>] [--config-url <url>] [--dry-run] [--no-reboot]"
            echo ""
            echo "  --config, -c       TOML config file (local path)"
            echo "  --config-url, -u   Download TOML config from URL"
            echo "  --dry-run, -n      Show what would be done without executing"
            echo "  --no-reboot        Don't reboot after installation"
            echo ""
            echo "Curl one-liner:"
            echo "  bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-install-hetzner.sh)"
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

# Download remote config if --config-url given
if [[ -n "$CONFIG_URL" ]]; then
    log_info "Downloading config: ${CONFIG_URL}"
    curl -sSfL -o /tmp/pve-config-remote.toml "$CONFIG_URL" || \
        die "Failed to download config from ${CONFIG_URL}"
    CONFIG_FILE="/tmp/pve-config-remote.toml"
fi

INTERACTIVE=true
[[ -n "$CONFIG_FILE" ]] && INTERACTIVE=false

# When run via curl pipe, redirect interactive reads from /dev/tty
if $INTERACTIVE && ! [ -t 0 ]; then
    exec 0</dev/tty
fi

# ---- Minimal TOML parser ----
parse_toml() {
    local file="$1" section="$2" key="$3" default="${4:-}"
    local val
    val=$(awk -v sec="[$section]" -v k="$key" '
        $0==sec{s=1;next} /^\[/{s=0}
        s && $0~"^"k"[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/,"")
            gsub(/^["'\'']/,""); gsub(/["'\'']\s*$/,"")
            print; exit
        }' "$file" 2>/dev/null)
    echo "${val:-$default}"
}

# Parse TOML array (returns space-separated values)
parse_toml_array() {
    local file="$1" section="$2" key="$3"
    awk -v sec="[$section]" -v k="$key" '
        $0==sec{s=1;next} /^\[/{s=0}
        s && $0~"^"k"[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/,"")
            gsub(/[\[\]"'\'']/,"")
            gsub(/,\s*/, " ")
            print; exit
        }' "$file" 2>/dev/null
}

# ============================================================
# DETECT HARDWARE
# ============================================================
detect_hardware() {
    log_step "Detecting hardware"

    # UEFI detection
    BOOT_MODE="bios"
    [[ -d /sys/firmware/efi ]] && BOOT_MODE="uefi"

    # Default interface
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$DEFAULT_INTERFACE" ]; then
        DEFAULT_INTERFACE=$(udevadm info -e | grep -m1 -A 20 ^P.*eth0 | grep ID_NET_NAME_PATH | cut -d'=' -f2)
    fi
    DEFAULT_INTERFACE="${DEFAULT_INTERFACE:-eno1}"

    # All interface names
    # All interface names (excluding lo)
    AVAILABLE_INTERFACES=$(ip -o link show | awk -F'[: ]+' '$2 != "lo" {printf "%s%s", (n++?", ":""), $2}')

    # Detect disks
    DETECTED_DISKS=$(lsblk -dpno NAME,TYPE | awk '$2=="disk"{print $1}' | grep -E "nvme|sd" | sort)
    DISK_COUNT=$(echo "$DETECTED_DISKS" | wc -l)

    # Detect rescue system codename (for APT repos)
    RESCUE_CODENAME=$(lsb_release -cs 2>/dev/null || cat /etc/os-release 2>/dev/null | grep VERSION_CODENAME | cut -d= -f2 || echo "bookworm")

    echo "  Boot mode:  ${BOOT_MODE}"
    echo "  Interface:  ${DEFAULT_INTERFACE} (available: ${AVAILABLE_INTERFACES})"
    echo "  Disks:      ${DISK_COUNT} found: $(echo $DETECTED_DISKS | tr '\n' ' ')"
    echo "  Rescue OS:  ${RESCUE_CODENAME}"
}

# Network from selected interface
detect_network_for_interface() {
    local iface="$1"
    MAIN_IPV4_CIDR=$(ip address show "$iface" 2>/dev/null | grep global | grep "inet " | xargs | cut -d" " -f2)
    MAIN_IPV4=$(echo "$MAIN_IPV4_CIDR" | cut -d'/' -f1)
    MAIN_IPV4_GW=$(ip route | grep default | xargs | cut -d" " -f3)
    MAC_ADDRESS=$(ip link show "$iface" | awk '/ether/ {print $2}')
    IPV6_CIDR=$(ip address show "$iface" 2>/dev/null | grep global | grep "inet6 " | xargs | cut -d" " -f2)
    MAIN_IPV6=$(echo "$IPV6_CIDR" | cut -d'/' -f1)
    if [ -n "$IPV6_CIDR" ]; then
        FIRST_IPV6_CIDR="$(echo "$IPV6_CIDR" | cut -d'/' -f1 | cut -d':' -f1-4):1::1/80"
    else
        FIRST_IPV6_CIDR=""
    fi
}

# ============================================================
# GATHER INPUTS
# ============================================================
get_inputs() {
    if $INTERACTIVE; then
        get_inputs_interactive
    else
        get_inputs_from_toml
    fi

    # Validate
    if [[ -z "$HOSTNAME" ]]; then die "Hostname required"; fi
    if [[ -z "$FQDN" ]]; then die "FQDN required"; fi
    if ! $DRY_RUN; then
        if [[ -z "$NEW_ROOT_PASSWORD" ]]; then die "Root password required"; fi
        if [[ ${#NEW_ROOT_PASSWORD} -lt 5 ]]; then die "Root password must be at least 5 characters (Proxmox requirement)"; fi
    fi
}

get_inputs_interactive() {
    echo -e "${CLR_YELLOW}--- Interactive Configuration ---${CLR_RESET}"
    read -e -p "Interface name (detected: ${AVAILABLE_INTERFACES}): " -i "${DEFAULT_INTERFACE}" INTERFACE_NAME
    RESCUE_INTERFACE="$INTERFACE_NAME"
    detect_network_for_interface "$INTERFACE_NAME"

    echo -e "${CLR_YELLOW}Detected: IPv4=${MAIN_IPV4_CIDR} GW=${MAIN_IPV4_GW} MAC=${MAC_ADDRESS}${CLR_RESET}"
    [[ -n "$MAIN_IPV6" ]] && echo -e "${CLR_YELLOW}  IPv6=${IPV6_CIDR}${CLR_RESET}"

    read -e -p "Hostname: " -i "proxmox" HOSTNAME
    read -e -p "FQDN: " -i "${HOSTNAME}.example.com" FQDN
    read -e -p "Timezone: " -i "UTC" TIMEZONE
    read -e -p "Admin email: " -i "admin@example.com" EMAIL
    read -e -p "Country (2-letter): " -i "us" COUNTRY
    KEYBOARD="en-us"

    # Disks
    echo -e "${CLR_YELLOW}Detected disks: $(echo $DETECTED_DISKS | tr '\n' ' ')${CLR_RESET}"
    read -e -p "Disk 1: " -i "$(echo "$DETECTED_DISKS" | head -1)" DISK1
    read -e -p "Disk 2: " -i "$(echo "$DETECTED_DISKS" | tail -1)" DISK2
    ZFS_RAID="raid1"
    FILESYSTEM="zfs"
    DNS1="185.12.64.1"
    DNS2="185.12.64.2"
    NET_SOURCE="from-dhcp"

    # Password
    while [[ -z "${NEW_ROOT_PASSWORD:-}" ]]; do
        read -s -p "Root password: " NEW_ROOT_PASSWORD < "${TTY_INPUT:-/dev/stdin}" || true; echo ""
    done
}

get_inputs_from_toml() {
    log_info "Reading config: ${CONFIG_FILE}"
    if [[ ! -f "$CONFIG_FILE" ]]; then die "Config not found: $CONFIG_FILE"; fi

    HOSTNAME=$(parse_toml "$CONFIG_FILE" server hostname "")
    FQDN=$(parse_toml "$CONFIG_FILE" server fqdn "")
    TIMEZONE=$(parse_toml "$CONFIG_FILE" server timezone "UTC")
    COUNTRY=$(parse_toml "$CONFIG_FILE" server country "us")
    KEYBOARD=$(parse_toml "$CONFIG_FILE" server keyboard "en-us")

    INTERFACE_NAME=$(parse_toml "$CONFIG_FILE" network interface "$DEFAULT_INTERFACE")
    DNS1=$(parse_toml "$CONFIG_FILE" network dns1 "185.12.64.1")
    DNS2=$(parse_toml "$CONFIG_FILE" network dns2 "185.12.64.2")
    NET_SOURCE=$(parse_toml "$CONFIG_FILE" network source "from-dhcp")

    # Rescue interface for IP/gateway detection — may differ from bare-metal name
    # Try TOML interface first; if it doesn't exist in rescue, fall back to auto-detected
    if ip link show "$INTERFACE_NAME" &>/dev/null; then
        RESCUE_INTERFACE="$INTERFACE_NAME"
    else
        RESCUE_INTERFACE="$DEFAULT_INTERFACE"
        log_warn "Interface '$INTERFACE_NAME' not found in rescue — using '$DEFAULT_INTERFACE' for detection"
    fi
    detect_network_for_interface "$RESCUE_INTERFACE"

    FILESYSTEM=$(parse_toml "$CONFIG_FILE" disk filesystem "zfs")
    ZFS_RAID=$(parse_toml "$CONFIG_FILE" disk zfs_raid "raid1")
    DISK_LIST=$(parse_toml_array "$CONFIG_FILE" disk disk_list)
    DISK1=$(echo "$DISK_LIST" | awk '{print $1}')
    DISK2=$(echo "$DISK_LIST" | awk '{print $2}')
    # Fallback to detected disks
    [[ -z "$DISK1" ]] && DISK1=$(echo "$DETECTED_DISKS" | head -1)
    [[ -z "$DISK2" ]] && DISK2=$(echo "$DETECTED_DISKS" | tail -1)

    EMAIL=$(parse_toml "$CONFIG_FILE" users email "admin@example.com")
    NEW_ROOT_PASSWORD=$(parse_toml "$CONFIG_FILE" users root_password "")

    # Prompt for password if empty (even in non-interactive)
    if ! $DRY_RUN && [[ -z "${NEW_ROOT_PASSWORD:-}" ]]; then
        if [[ -n "$TTY_INPUT" ]]; then
            while [[ -z "${NEW_ROOT_PASSWORD:-}" ]]; do
                read -s -p "Root password (not in config — enter now): " NEW_ROOT_PASSWORD < "$TTY_INPUT" || true
                echo ""
            done
        else
            die "Root password required but no terminal available for interactive prompt. Set root_password in config TOML."
        fi
    fi

    echo "  Hostname:  ${HOSTNAME}"
    echo "  FQDN:      ${FQDN}"
    echo "  Interface: ${INTERFACE_NAME}"
    echo "  IPv4:      ${MAIN_IPV4_CIDR}"
    echo "  Gateway:   ${MAIN_IPV4_GW}"
    echo "  Disks:     ${DISK1}, ${DISK2}"
    echo "  ZFS RAID:  ${ZFS_RAID}"
}

# ============================================================
# PRE-FLIGHT VALIDATION
# ============================================================
preflight_checks() {
    log_step "Pre-flight validation"
    local errors=0

    # Check we're in rescue system (not already in Proxmox)
    if command -v pveversion &>/dev/null; then
        log_warn "pveversion found — are you sure you're in rescue mode?"
    fi

    # Check disks exist
    if [[ ! -b "$DISK1" ]]; then
        log_err "Disk 1 not found: $DISK1"
        errors=$((errors + 1))
    else
        local size1
        size1=$(lsblk -bno SIZE "$DISK1" 2>/dev/null | head -1)
        log_ok "Disk 1: $DISK1 ($(( size1 / 1024 / 1024 / 1024 )) GB)"
    fi

    if [[ ! -b "$DISK2" ]]; then
        log_err "Disk 2 not found: $DISK2"
        errors=$((errors + 1))
    else
        local size2
        size2=$(lsblk -bno SIZE "$DISK2" 2>/dev/null | head -1)
        log_ok "Disk 2: $DISK2 ($(( size2 / 1024 / 1024 / 1024 )) GB)"
    fi

    # Check network — interface name in config may differ from rescue
    if ip link show "$INTERFACE_NAME" &>/dev/null; then
        log_ok "Interface: $INTERFACE_NAME (IPv4: $MAIN_IPV4_CIDR)"
    elif [[ -n "${RESCUE_INTERFACE:-}" ]] && ip link show "$RESCUE_INTERFACE" &>/dev/null; then
        log_ok "Interface: $INTERFACE_NAME (bare-metal) — using $RESCUE_INTERFACE in rescue"
        log_ok "  IPv4: $MAIN_IPV4_CIDR  GW: $MAIN_IPV4_GW"
    else
        log_err "No usable network interface — $INTERFACE_NAME not found"
        errors=$((errors + 1))
    fi

    # Verify we actually got an IP
    if [[ -z "$MAIN_IPV4" ]]; then
        log_err "No IPv4 address detected"
        errors=$((errors + 1))
    fi

    # Check UEFI + OVMF availability
    if [[ "$BOOT_MODE" == "uefi" ]]; then
        log_info "UEFI boot detected — will use OVMF firmware with persistent NVRAM"
        # OVMF files will be checked after package install (in prepare_packages)
    else
        log_info "Legacy BIOS boot detected"
    fi

    # Check KVM support
    if [[ ! -e /dev/kvm ]]; then
        log_err "KVM not available (/dev/kvm missing) — cannot run QEMU with -enable-kvm"
        errors=$((errors + 1))
    else
        log_ok "KVM available"
    fi

    # Check RAM (need at least 4GB for QEMU)
    local total_ram_mb
    total_ram_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    if [[ $total_ram_mb -lt 4096 ]]; then
        log_warn "Only ${total_ram_mb}MB RAM — QEMU needs 4GB, may fail"
    else
        log_ok "RAM: ${total_ram_mb}MB available"
    fi

    if [[ $errors -gt 0 ]]; then die "Pre-flight failed with $errors error(s)"; fi
    log_ok "All pre-flight checks passed"
}

# ============================================================
# PREPARE
# ============================================================
prepare_packages() {
    log_step "Installing packages"

    # Auto-detect codename for Proxmox APT repo
    # Hetzner rescue systems are typically Debian bookworm or trixie
    local codename="$RESCUE_CODENAME"
    # Proxmox repo only has bookworm and trixie; fall back to bookworm
    case "$codename" in
        bookworm|trixie) ;;
        *) codename="bookworm"; log_warn "Unknown codename '$RESCUE_CODENAME', using bookworm" ;;
    esac

    echo "deb http://download.proxmox.com/debian/pve ${codename} pve-no-subscription" \
        | tee /etc/apt/sources.list.d/pve.list >/dev/null
    log_debug "APT repo: pve ${codename} pve-no-subscription"
    curl -so /etc/apt/trusted.gpg.d/proxmox-release-${codename}.gpg \
        "https://enterprise.proxmox.com/debian/proxmox-release-${codename}.gpg"
    log_debug "Running apt update + install..."
    apt clean && apt update -qq && apt install -yq proxmox-auto-install-assistant xorriso ovmf wget sshpass
    log_debug "Installed: proxmox-auto-install-assistant xorriso ovmf wget sshpass"

    # Verify OVMF files for UEFI mode
    if [[ "$BOOT_MODE" == "uefi" ]]; then
        locate_ovmf_firmware
    fi

    log_ok "Packages ready"
}

# Locate OVMF firmware files — we need split CODE+VARS for persistent NVRAM
locate_ovmf_firmware() {
    # Prefer 4M variant (modern, supports Secure Boot vars), fall back to legacy
    if [[ -f /usr/share/OVMF/OVMF_CODE_4M.fd ]]; then
        OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
        OVMF_VARS_TEMPLATE="/usr/share/OVMF/OVMF_VARS_4M.fd"
    elif [[ -f /usr/share/OVMF/OVMF_CODE.fd ]]; then
        OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
        OVMF_VARS_TEMPLATE="/usr/share/OVMF/OVMF_VARS.fd"
    elif [[ -f /usr/share/ovmf/OVMF.fd ]]; then
        # Fallback: combined firmware (no persistent NVRAM — less safe)
        OVMF_CODE=""
        OVMF_VARS_TEMPLATE=""
        log_warn "Only combined OVMF.fd found — UEFI NVRAM will NOT persist between steps"
        log_warn "Boot may rely on fallback EFI path (\\EFI\\BOOT\\BOOTX64.EFI)"
        return
    else
        die "UEFI mode but no OVMF firmware found. Install: apt install ovmf"
    fi

    if [[ ! -f "$OVMF_VARS_TEMPLATE" ]]; then
        die "OVMF_VARS template not found: $OVMF_VARS_TEMPLATE"
    fi

    log_ok "OVMF firmware: $OVMF_CODE"
    log_ok "OVMF VARS template: $OVMF_VARS_TEMPLATE"
}

# Build QEMU UEFI arguments — with writable NVRAM copy
# The NVRAM file persists between install_proxmox and boot_and_configure
OVMF_NVRAM_COPY="/root/ovmf-vars-session.fd"

build_uefi_args() {
    if [[ "$BOOT_MODE" != "uefi" ]]; then
        echo ""
        return
    fi

    if [[ -n "${OVMF_CODE:-}" && -n "${OVMF_VARS_TEMPLATE:-}" ]]; then
        # Split firmware: CODE (readonly) + VARS (writable copy)
        # Copy VARS template only if we don't already have a session copy
        # (install step creates it, configure step reuses it)
        if [[ ! -f "$OVMF_NVRAM_COPY" ]]; then
            cp "$OVMF_VARS_TEMPLATE" "$OVMF_NVRAM_COPY"
            log_info "Created writable NVRAM: $OVMF_NVRAM_COPY"
        else
            log_info "Reusing NVRAM from install step: $OVMF_NVRAM_COPY"
        fi
        echo "-drive if=pflash,format=raw,readonly=on,file=${OVMF_CODE} -drive if=pflash,format=raw,file=${OVMF_NVRAM_COPY}"
    else
        # Fallback: combined firmware (no persistent NVRAM)
        echo "-bios /usr/share/ovmf/OVMF.fd"
    fi
}

get_latest_iso_url() {
    local base="https://enterprise.proxmox.com/iso/"
    curl -s "$base" | grep -oP 'proxmox-ve_[0-9]+\.[0-9]+-[0-9]+\.iso' | sort -V | tail -n1 | \
        awk -v b="$base" '{print b $0}'
}

download_iso() {
    log_step "Downloading Proxmox ISO"
    if [[ -f "pve.iso" ]]; then
        log_warn "ISO exists, skipping download (delete /root/pve.iso to force re-download)"
        return
    fi
    local url
    url=$(get_latest_iso_url)
    if [[ -z "$url" ]]; then die "Failed to find ISO URL at enterprise.proxmox.com/iso/"; fi
    log_info "URL: $url"
    log_debug "Downloading (~1GB, may take a few minutes)..."
    wget -q --show-progress -O pve.iso "$url"
    local iso_size
    iso_size=$(du -h pve.iso | cut -f1)
    log_ok "ISO downloaded (${iso_size})"
}

# ============================================================
# GENERATE answer.toml FOR PROXMOX AUTO-INSTALLER
# ============================================================
# CRITICAL: Inside QEMU, physical disks (/dev/nvme0n1, /dev/nvme1n1) appear
# as virtio devices (/dev/vda, /dev/vdb). The Proxmox auto-installer runs
# INSIDE QEMU, so it sees virtio names, NOT the physical NVMe paths.
#
# SOLUTION: We omit disk-list entirely. Since QEMU only has the 2 disks we
# passed via -drive, the Proxmox installer auto-discovers them. This works
# regardless of the virtio device naming and is the most robust approach.
#
# The physical disk paths from the TOML config are only used for the QEMU
# -drive arguments (host side), never inside the guest answer.toml.
make_answer_toml() {
    log_step "Generating answer.toml for Proxmox auto-installer"

    cat > answer.toml << EOF
[global]
keyboard = "${KEYBOARD}"
country = "${COUNTRY}"
fqdn = "${FQDN}"
mailto = "${EMAIL}"
timezone = "${TIMEZONE}"
root-password = "${NEW_ROOT_PASSWORD}"
reboot-on-error = false

[network]
source = "${NET_SOURCE}"

[disk-setup]
filesystem = "${FILESYSTEM}"
EOF

    # Add ZFS-specific config only for ZFS
    if [[ "$FILESYSTEM" == "zfs" ]]; then
        cat >> answer.toml << EOF
zfs.raid = "${ZFS_RAID}"
EOF
    fi

    # NOTE: disk-list is intentionally omitted.
    # Inside QEMU, the only disks are the two we pass via -drive (as virtio).
    # The Proxmox installer auto-discovers all available disks.
    # This avoids the /dev/nvme0n1 vs /dev/vda naming mismatch.

    echo ""
    log_info "answer.toml contents:"
    echo -e "${CLR_YELLOW}"
    cat answer.toml
    echo -e "${CLR_RESET}"
    log_ok "answer.toml created (disk-list omitted — auto-discovery inside QEMU)"
}

make_autoinstall_iso() {
    log_step "Building autoinstall ISO"
    log_cmd "proxmox-auto-install-assistant prepare-iso pve.iso --fetch-from iso --answer-file answer.toml --output pve-autoinstall.iso"
    proxmox-auto-install-assistant prepare-iso pve.iso \
        --fetch-from iso --answer-file answer.toml --output pve-autoinstall.iso
    local iso_size
    iso_size=$(du -h pve-autoinstall.iso | cut -f1)
    log_ok "pve-autoinstall.iso ready (${iso_size})"
}

# ============================================================
# INSTALL VIA QEMU
# ============================================================
install_proxmox() {
    log_step "Installing Proxmox via QEMU"

    local uefi_args
    uefi_args=$(build_uefi_args)

    log_info "Boot mode: ${BOOT_MODE}"
    log_info "QEMU drives: ${DISK1} → virtio (vda), ${DISK2} → virtio (vdb)"
    [[ -n "$uefi_args" ]] && log_info "UEFI args: ${uefi_args}"
    echo ""
    log_warn "Do NOT interrupt — installation takes ~5-10 min"
    log_warn "QEMU runs headless (no display). Output suppressed."
    echo ""

    local qemu_cmd="qemu-system-x86_64 \
        -enable-kvm ${uefi_args} \
        -cpu host -smp 4 -m 4096 \
        -boot d -cdrom ./pve-autoinstall.iso \
        -drive file=${DISK1},format=raw,media=disk,if=virtio \
        -drive file=${DISK2},format=raw,media=disk,if=virtio \
        -no-reboot -display none"

    log_info "Command: $(echo $qemu_cmd | tr -s ' ')"
    echo ""
    log_info "Starting QEMU install (logging to /tmp/qemu-install.log)..."

    eval $qemu_cmd > /tmp/qemu-install.log 2>&1 &
    local qemu_install_pid=$!
    log_debug "QEMU PID: $qemu_install_pid"

    # Progress indicator while QEMU runs
    local elapsed=0
    echo -n "  Installing"
    while kill -0 $qemu_install_pid 2>/dev/null; do
        echo -n "."
        sleep 10
        elapsed=$((elapsed + 10))
        if (( elapsed % 60 == 0 )); then
            echo -n " [${elapsed}s]"
        fi
    done
    echo ""

    wait $qemu_install_pid 2>/dev/null
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        log_err "QEMU exited with code $rc"
        log_err "Last 20 lines of /tmp/qemu-install.log:"
        tail -20 /tmp/qemu-install.log
        die "Installation failed — check /tmp/qemu-install.log"
    fi

    log_ok "Proxmox installation complete"
}

# ============================================================
# POST-INSTALL CONFIGURATION VIA SSH
# ============================================================
boot_and_configure() {
    log_step "Post-install configuration via SSH"

    local uefi_args
    uefi_args=$(build_uefi_args)

    log_info "Booting installed system in QEMU (SSH on port 5555)..."
    log_debug "QEMU config: -cpu host -smp 4 -m 4096, drives: ${DISK1} + ${DISK2}"
    log_debug "Port forward: localhost:5555 → guest:22"

    nohup qemu-system-x86_64 -enable-kvm ${uefi_args} \
        -cpu host -device e1000,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::5555-:22 \
        -smp 4 -m 4096 \
        -drive file=${DISK1},format=raw,media=disk,if=virtio \
        -drive file=${DISK2},format=raw,media=disk,if=virtio \
        -display none > /tmp/qemu-configure.log 2>&1 &
    QEMU_PID=$!

    log_info "QEMU PID: $QEMU_PID"
    echo -n "  Waiting for SSH"
    for i in $(seq 1 60); do
        if nc -z localhost 5555 2>/dev/null; then
            echo -e " ${CLR_GREEN}ready${CLR_RESET}"
            break
        fi
        echo -n "."
        sleep 5
        if [[ $i -eq 60 ]]; then
            echo ""
            log_err "SSH timeout after 5 min"
            log_err "Last 20 lines of /tmp/qemu-configure.log:"
            tail -20 /tmp/qemu-configure.log
            kill $QEMU_PID 2>/dev/null || true
            die "Could not connect to installed system — check UEFI boot"
        fi
    done

    local SSH="sshpass -p ${NEW_ROOT_PASSWORD} ssh -p 5555 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@localhost"
    local SCP="sshpass -p ${NEW_ROOT_PASSWORD} scp -P 5555 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

    ssh-keygen -f "/root/.ssh/known_hosts" -R "[localhost]:5555" 2>/dev/null || true

    # Verify we can actually connect
    if ! $SSH "hostname" &>/dev/null; then
        log_err "SSH connected but authentication failed"
        kill $QEMU_PID 2>/dev/null || true
        die "Cannot authenticate — password mismatch?"
    fi
    local installed_hostname
    installed_hostname=$($SSH "hostname" 2>/dev/null)
    log_ok "Connected to installed system (hostname: ${installed_hostname})"

    # Verify UEFI boot entries (if applicable)
    if [[ "$BOOT_MODE" == "uefi" ]]; then
        log_info "Checking UEFI boot configuration inside installed system..."
        local efi_check
        efi_check=$($SSH "ls -la /boot/efi/EFI/ 2>/dev/null && efibootmgr 2>/dev/null || echo 'efibootmgr not available'" 2>/dev/null)
        echo "$efi_check" | head -20
        # Check for EFI System Partition
        local esp_check
        esp_check=$($SSH "findmnt /boot/efi 2>/dev/null || echo 'ESP not mounted'" 2>/dev/null)
        log_info "ESP mount: $esp_check"
        # Ensure fallback boot path exists
        if $SSH "[ -f /boot/efi/EFI/BOOT/BOOTX64.EFI ]" 2>/dev/null; then
            log_ok "EFI fallback bootloader present (\\EFI\\BOOT\\BOOTX64.EFI)"
        else
            log_warn "EFI fallback bootloader NOT found — bare metal boot may fail"
            log_warn "Will attempt to create fallback from systemd-boot or grub"
            $SSH '
                mkdir -p /boot/efi/EFI/BOOT
                # Try systemd-boot first (PVE 8+)
                if [ -f /boot/efi/EFI/systemd/systemd-bootx64.efi ]; then
                    cp /boot/efi/EFI/systemd/systemd-bootx64.efi /boot/efi/EFI/BOOT/BOOTX64.EFI
                # Try grub
                elif [ -f /boot/efi/EFI/proxmox/grubx64.efi ]; then
                    cp /boot/efi/EFI/proxmox/grubx64.efi /boot/efi/EFI/BOOT/BOOTX64.EFI
                fi
            ' 2>/dev/null || true
            if $SSH "[ -f /boot/efi/EFI/BOOT/BOOTX64.EFI ]" 2>/dev/null; then
                log_ok "EFI fallback bootloader created"
            else
                log_warn "Could not create EFI fallback — bare metal boot may require manual fix"
            fi
        fi
    fi

    # ---- Detect the installed system's interface name ----
    # The Proxmox auto-installer may enable interface pinning (nic0, nic1...)
    # which differs from the rescue interface name. Read what the installer chose.
    log_info "Detecting installed system interface name..."
    INSTALL_INTERFACE=$($SSH "awk '/bridge-ports/{print \$2}' /etc/network/interfaces 2>/dev/null" 2>/dev/null || true)
    if [[ -z "$INSTALL_INTERFACE" ]]; then
        # No bridge found — check for direct interface
        INSTALL_INTERFACE=$($SSH "grep -E '^iface .* inet' /etc/network/interfaces 2>/dev/null | grep -v lo | awk '{print \$2}' | head -1" 2>/dev/null || true)
    fi
    if [[ -z "$INSTALL_INTERFACE" ]]; then
        # Last resort: use non-loopback interface from running system
        INSTALL_INTERFACE=$($SSH "ip -o link show | awk -F': ' '!/lo:/{print \$2; exit}'" 2>/dev/null || true)
    fi
    INSTALL_INTERFACE="${INSTALL_INTERFACE:-${INTERFACE_NAME:-nic0}}"

    # Check if this is a QEMU virtual NIC (ens3/enp0s*) — if so, use nic0
    # because Proxmox interface pinning will map nic0 to the real NIC on bare metal
    if [[ "$INSTALL_INTERFACE" =~ ^(ens|enp0s) ]]; then
        log_info "Detected QEMU virtual NIC '$INSTALL_INTERFACE' — checking for interface pinning..."
        if $SSH "ls /etc/systemd/network/*pve* 2>/dev/null" &>/dev/null; then
            INSTALL_INTERFACE="nic0"
            log_ok "Proxmox interface pinning active → using 'nic0' for bare-metal config"
        else
            log_warn "No interface pinning found — using TOML interface '${INTERFACE_NAME}'"
            INSTALL_INTERFACE="${INTERFACE_NAME}"
        fi
    else
        log_ok "Installed system interface: $INSTALL_INTERFACE"
    fi

    # ---- Generate and push config files ----
    log_info "Configuring network, hostname, DNS (interface: $INSTALL_INTERFACE)..."

    # /etc/hosts
    log_debug "Writing /etc/hosts"
    cat > /tmp/pve-hosts << EOF
127.0.0.1 localhost.localdomain localhost
${MAIN_IPV4} ${FQDN} ${HOSTNAME}
# IPv6
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
EOF
    [[ -n "$MAIN_IPV6" ]] && echo "${MAIN_IPV6} ${FQDN} ${HOSTNAME}" >> /tmp/pve-hosts
    $SCP /tmp/pve-hosts root@localhost:/etc/hosts
    log_debug "  /etc/hosts pushed"

    # /etc/network/interfaces
    log_debug "Writing /etc/network/interfaces"
    cat > /tmp/pve-interfaces << EOF
# Network interface configuration — generated by pve-install-hetzner.sh
auto lo
iface lo inet loopback

iface ${INSTALL_INTERFACE} inet manual

auto vmbr0
iface vmbr0 inet static
    address ${MAIN_IPV4_CIDR}
    gateway ${MAIN_IPV4_GW}
    bridge-ports ${INSTALL_INTERFACE}
    bridge-stp off
    bridge-fd 0
EOF
    if [[ -n "$IPV6_CIDR" ]]; then
        cat >> /tmp/pve-interfaces << EOF

iface vmbr0 inet6 static
    address ${FIRST_IPV6_CIDR}
    gateway fe80::1
EOF
    fi
    $SCP /tmp/pve-interfaces root@localhost:/etc/network/interfaces
    log_debug "  /etc/network/interfaces pushed"

    # /etc/resolv.conf
    log_debug "Writing /etc/resolv.conf + /etc/hostname"
    $SSH "printf 'search ${FQDN#*.}\nnameserver ${DNS1}\nnameserver ${DNS2}\n' > /etc/resolv.conf"

    # /etc/hostname
    $SSH "echo ${HOSTNAME} > /etc/hostname"
    log_debug "  hostname=${HOSTNAME}, search=${FQDN#*.}"

    # Sysctl baseline
    log_debug "Writing /etc/sysctl.d/99-proxmox.conf"
    cat > /tmp/pve-sysctl << 'EOF'
net.netfilter.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_tcp_timeout_established=28800
EOF
    $SCP /tmp/pve-sysctl root@localhost:/etc/sysctl.d/99-proxmox.conf
    log_debug "  sysctl pushed"

    # Disable enterprise repos, enable community
    log_debug "Disabling enterprise repos, disabling rpcbind"
    $SSH "[ -f /etc/apt/sources.list ] && mv /etc/apt/sources.list /etc/apt/sources.list.bak || true"
    $SSH "for f in /etc/apt/sources.list.d/pve-enterprise.* /etc/apt/sources.list.d/ceph*; do [ -f \"\$f\" ] && mv \"\$f\" \"\${f}.disabled\"; done || true"

    # Disable rpcbind
    $SSH "systemctl disable --now rpcbind rpcbind.socket 2>/dev/null || true"

    # Show disk layout for verification
    log_info "Installed disk layout:"
    $SSH "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null" || true
    echo ""
    if [[ "$FILESYSTEM" == "zfs" ]]; then
        log_info "ZFS pool status:"
        $SSH "zpool status 2>/dev/null" || true
    fi

    # Shutdown VM
    log_info "Shutting down VM (PID: $QEMU_PID)..."
    $SSH 'poweroff' || true
    log_debug "Waiting for QEMU to exit..."
    wait $QEMU_PID 2>/dev/null || true
    log_debug "QEMU exited"

    # Clean up session NVRAM (not needed after configuration)
    rm -f "$OVMF_NVRAM_COPY"

    log_ok "Post-configuration complete"
}

# ============================================================
# DRY RUN
# ============================================================
dry_run_summary() {
    log_step "DRY RUN — No changes will be made"
    echo ""
    echo "  ┌─ Server ────────────────────────────────────"
    echo "  │ Hostname:   ${HOSTNAME}"
    echo "  │ FQDN:       ${FQDN}"
    echo "  │ Country:    ${COUNTRY}"
    echo "  │ Timezone:   ${TIMEZONE}"
    echo "  │ Keyboard:   ${KEYBOARD}"
    echo "  │ Email:      ${EMAIL}"
    echo "  │"
    echo "  ├─ Network ───────────────────────────────────"
    echo "  │ Interface:  ${INTERFACE_NAME}"
    echo "  │ IPv4 CIDR:  ${MAIN_IPV4_CIDR}"
    echo "  │ Gateway:    ${MAIN_IPV4_GW}"
    echo "  │ MAC:        ${MAC_ADDRESS}"
    echo "  │ IPv6:       ${IPV6_CIDR:-none}"
    echo "  │ DNS:        ${DNS1}, ${DNS2}"
    echo "  │"
    echo "  ├─ Disks ─────────────────────────────────────"
    echo "  │ Filesystem: ${FILESYSTEM}"
    echo "  │ RAID:       ${ZFS_RAID}"
    echo "  │ Disk 1:     ${DISK1} (host) → /dev/vda (QEMU)"
    echo "  │ Disk 2:     ${DISK2} (host) → /dev/vdb (QEMU)"
    echo "  │"
    echo "  ├─ Boot ──────────────────────────────────────"
    echo "  │ Mode:       ${BOOT_MODE}"
    if [[ "$BOOT_MODE" == "uefi" ]]; then
    echo "  │ OVMF:       split CODE+VARS with persistent NVRAM"
    echo "  │ Fallback:   will ensure \\EFI\\BOOT\\BOOTX64.EFI exists"
    fi
    echo "  └─────────────────────────────────────────────"
    echo ""
    echo "  answer.toml for Proxmox auto-installer:"
    echo -e "  ${CLR_YELLOW}NOTE: disk-list is intentionally OMITTED${CLR_RESET}"
    echo "  Inside QEMU, the only visible disks are the two virtio drives."
    echo "  The Proxmox installer auto-discovers them — no name mapping needed."
    echo ""
    echo "  Steps that would execute:"
    echo "    1. Pre-flight checks (disks, KVM, interface, UEFI)"
    echo "    2. Install packages (proxmox-auto-install-assistant, xorriso, ovmf)"
    echo "    3. Download latest Proxmox VE ISO"
    echo "    4. Generate answer.toml (without disk-list)"
    echo "    5. Build autoinstall ISO"
    echo "    6. Install via QEMU: ${DISK1} + ${DISK2} as virtio drives"
    echo "    7. Boot VM with persistent UEFI NVRAM, configure via SSH"
    echo "    8. Verify UEFI boot entries + fallback bootloader"
    echo "    9. Configure: hostname, network, DNS, sysctl, repos"
    echo "   10. Reboot into Proxmox on bare metal"
    echo ""
    echo "  Post-install: run pve-harden.sh with matching TOML"
}

# ============================================================
# MAIN
# ============================================================
clear
echo -e "${CLR_GREEN}╔═══════════════════════════════════════════════╗${CLR_RESET}"
echo -e "${CLR_GREEN}║  Proxmox VE Installer for Hetzner Dedicated  ║${CLR_RESET}"
echo -e "${CLR_GREEN}║  Based on ariadata/proxmox-hetzner (MIT)      ║${CLR_RESET}"
echo -e "${CLR_GREEN}╚═══════════════════════════════════════════════╝${CLR_RESET}"
echo ""

detect_hardware
get_inputs

if $DRY_RUN; then
    preflight_checks
    dry_run_summary
    exit 0
fi

preflight_checks

# Confirm before proceeding (even non-interactive)
echo ""
echo -e "${CLR_RED}╔═══════════════════════════════════════════════════════╗${CLR_RESET}"
echo -e "${CLR_RED}║  WARNING: This will COMPLETELY ERASE both disks:     ║${CLR_RESET}"
echo -e "${CLR_RED}║    ${DISK1}$(printf '%*s' $((38 - ${#DISK1})) '')║${CLR_RESET}"
echo -e "${CLR_RED}║    ${DISK2}$(printf '%*s' $((38 - ${#DISK2})) '')║${CLR_RESET}"
echo -e "${CLR_RED}║  ALL DATA WILL BE DESTROYED!                         ║${CLR_RESET}"
echo -e "${CLR_RED}╚═══════════════════════════════════════════════════════╝${CLR_RESET}"
echo ""
if $INTERACTIVE; then
    read -p "Type 'yes' to continue: " CONFIRM < "${TTY_INPUT:-/dev/stdin}" || true
    [[ "$CONFIRM" != "yes" ]] && { echo "Aborted."; exit 0; }
else
    echo -e "${CLR_YELLOW}Non-interactive mode — proceeding in 10 seconds...${CLR_RESET}"
    echo -e "${CLR_YELLOW}Press Ctrl+C to abort${CLR_RESET}"
    sleep 10
fi

prepare_packages
download_iso
make_answer_toml
make_autoinstall_iso
install_proxmox
boot_and_configure

local elapsed=$(( $(date +%s) - SCRIPT_START ))
local mins=$(( elapsed / 60 ))
local secs=$(( elapsed % 60 ))

echo ""
echo -e "${CLR_GREEN}╔═══════════════════════════════════════════════════════╗${CLR_RESET}"
echo -e "${CLR_GREEN}║  Installation complete! (${mins}m ${secs}s)$(printf '%*s' $((24 - ${#mins} - ${#secs})) '')║${CLR_RESET}"
echo -e "${CLR_GREEN}║  Access: https://${MAIN_IPV4}:8006$(printf '%*s' $((27 - ${#MAIN_IPV4})) '')║${CLR_RESET}"
echo -e "${CLR_GREEN}╚═══════════════════════════════════════════════════════╝${CLR_RESET}"
echo ""
echo "Next steps:"
echo "  1. Reboot into Proxmox"
echo "  2. Run: bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-harden.sh) <config.toml>"
echo ""

if $SKIP_REBOOT; then
    log_warn "Skipping reboot (--no-reboot)"
else
    if $INTERACTIVE; then
        read -p "Reboot now? (y/n): " DO_REBOOT < "${TTY_INPUT:-/dev/stdin}" || true
        [[ "$DO_REBOOT" == "y" ]] && reboot
    else
        echo -e "${CLR_YELLOW}Rebooting in 10 seconds...${CLR_RESET}"
        sleep 10
        reboot
    fi
fi
