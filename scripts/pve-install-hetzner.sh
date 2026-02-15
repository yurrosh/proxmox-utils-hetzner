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

set -e
cd /root

# ---- Colors ----
CLR_RED="\033[1;31m"
CLR_GREEN="\033[1;32m"
CLR_YELLOW="\033[1;33m"
CLR_BLUE="\033[1;34m"
CLR_RESET="\033[m"

# ---- Ensure root ----
[[ $EUID -ne 0 ]] && { echo -e "${CLR_RED}Must run as root${CLR_RESET}"; exit 1; }

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
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Download remote config if --config-url given
if [[ -n "$CONFIG_URL" ]]; then
    echo -e "${CLR_BLUE}Downloading config: ${CONFIG_URL}${CLR_RESET}"
    curl -sSfL -o /tmp/pve-config-remote.toml "$CONFIG_URL" || {
        echo -e "${CLR_RED}Failed to download config from ${CONFIG_URL}${CLR_RESET}"; exit 1;
    }
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
    echo -e "${CLR_BLUE}Detecting hardware...${CLR_RESET}"

    # Default interface
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$DEFAULT_INTERFACE" ]; then
        DEFAULT_INTERFACE=$(udevadm info -e | grep -m1 -A 20 ^P.*eth0 | grep ID_NET_NAME_PATH | cut -d'=' -f2)
    fi
    DEFAULT_INTERFACE="${DEFAULT_INTERFACE:-eno1}"

    # All interface names
    AVAILABLE_INTERFACES=$(ip -d link show | grep -v "lo:" | grep -E '(^[0-9]+:|altname)' | \
        awk '/^[0-9]+:/ {iface=$2; gsub(/:/, "", iface); printf "%s", iface} /altname/ {printf ",%s", $2} END {print ""}' | sed 's/,$//')

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

    # Detect disks
    DETECTED_DISKS=$(lsblk -dpno NAME,TYPE | awk '$2=="disk"{print $1}' | grep -E "nvme|sd" | sort)
    DISK_COUNT=$(echo "$DETECTED_DISKS" | wc -l)

    echo -e "  Interface: ${DEFAULT_INTERFACE} (available: ${AVAILABLE_INTERFACES})"
    echo -e "  Disks: ${DISK_COUNT} found: $(echo $DETECTED_DISKS | tr '\n' ' ')"
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
    [[ -z "$HOSTNAME" ]] && { echo -e "${CLR_RED}Hostname required${CLR_RESET}"; exit 1; }
    [[ -z "$FQDN" ]] && { echo -e "${CLR_RED}FQDN required${CLR_RESET}"; exit 1; }
    [[ -z "$NEW_ROOT_PASSWORD" ]] && { echo -e "${CLR_RED}Root password required${CLR_RESET}"; exit 1; }
}

get_inputs_interactive() {
    echo -e "${CLR_YELLOW}--- Interactive Configuration ---${CLR_RESET}"
    read -e -p "Interface name (detected: ${AVAILABLE_INTERFACES}): " -i "${DEFAULT_INTERFACE}" INTERFACE_NAME
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
        read -s -p "Root password: " NEW_ROOT_PASSWORD; echo ""
    done
}

get_inputs_from_toml() {
    echo -e "${CLR_BLUE}Reading config: ${CONFIG_FILE}${CLR_RESET}"
    [[ ! -f "$CONFIG_FILE" ]] && { echo -e "${CLR_RED}Config not found: $CONFIG_FILE${CLR_RESET}"; exit 1; }

    HOSTNAME=$(parse_toml "$CONFIG_FILE" server hostname "")
    FQDN=$(parse_toml "$CONFIG_FILE" server fqdn "")
    TIMEZONE=$(parse_toml "$CONFIG_FILE" server timezone "UTC")
    COUNTRY=$(parse_toml "$CONFIG_FILE" server country "us")
    KEYBOARD=$(parse_toml "$CONFIG_FILE" server keyboard "en-us")

    INTERFACE_NAME=$(parse_toml "$CONFIG_FILE" network interface "$DEFAULT_INTERFACE")
    DNS1=$(parse_toml "$CONFIG_FILE" network dns1 "185.12.64.1")
    DNS2=$(parse_toml "$CONFIG_FILE" network dns2 "185.12.64.2")
    NET_SOURCE=$(parse_toml "$CONFIG_FILE" network source "from-dhcp")

    detect_network_for_interface "$INTERFACE_NAME"

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
    while [[ -z "$NEW_ROOT_PASSWORD" ]]; do
        read -s -p "Root password (not in config — enter now): " NEW_ROOT_PASSWORD; echo ""
    done

    echo -e "  Hostname:  ${HOSTNAME}"
    echo -e "  FQDN:      ${FQDN}"
    echo -e "  Interface: ${INTERFACE_NAME}"
    echo -e "  IPv4:      ${MAIN_IPV4_CIDR}"
    echo -e "  Gateway:   ${MAIN_IPV4_GW}"
    echo -e "  Disks:     ${DISK1}, ${DISK2}"
    echo -e "  ZFS RAID:  ${ZFS_RAID}"
}

# ============================================================
# PREPARE
# ============================================================
prepare_packages() {
    echo -e "${CLR_BLUE}Installing packages...${CLR_RESET}"
    echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" | tee /etc/apt/sources.list.d/pve.list >/dev/null
    curl -so /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg \
        https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg
    apt clean && apt update -qq && apt install -yq proxmox-auto-install-assistant xorriso ovmf wget sshpass
    echo -e "${CLR_GREEN}Packages ready${CLR_RESET}"
}

get_latest_iso_url() {
    local base="https://enterprise.proxmox.com/iso/"
    curl -s "$base" | grep -oP 'proxmox-ve_[0-9]+\.[0-9]+-[0-9]+\.iso' | sort -V | tail -n1 | \
        awk -v b="$base" '{print b $0}'
}

download_iso() {
    if [[ -f "pve.iso" ]]; then
        echo -e "${CLR_YELLOW}ISO exists, skipping download${CLR_RESET}"
        return
    fi
    echo -e "${CLR_BLUE}Downloading Proxmox ISO...${CLR_RESET}"
    local url
    url=$(get_latest_iso_url)
    [[ -z "$url" ]] && { echo -e "${CLR_RED}Failed to find ISO URL${CLR_RESET}"; exit 1; }
    echo "  URL: $url"
    wget -q --show-progress -O pve.iso "$url"
    echo -e "${CLR_GREEN}ISO downloaded${CLR_RESET}"
}

# ============================================================
# GENERATE answer.toml FOR PROXMOX AUTO-INSTALLER
# ============================================================
make_answer_toml() {
    echo -e "${CLR_BLUE}Generating answer.toml...${CLR_RESET}"
    cat > answer.toml << EOF
[global]
    keyboard = "${KEYBOARD}"
    country = "${COUNTRY}"
    fqdn = "${FQDN}"
    mailto = "${EMAIL}"
    timezone = "${TIMEZONE}"
    root_password = "${NEW_ROOT_PASSWORD}"
    reboot_on_error = false

[network]
    source = "${NET_SOURCE}"

[disk-setup]
    filesystem = "${FILESYSTEM}"
    zfs.raid = "${ZFS_RAID}"
    disk_list = ["${DISK1}", "${DISK2}"]

EOF
    echo -e "${CLR_GREEN}answer.toml created${CLR_RESET}"
}

make_autoinstall_iso() {
    echo -e "${CLR_BLUE}Building autoinstall ISO...${CLR_RESET}"
    proxmox-auto-install-assistant prepare-iso pve.iso \
        --fetch-from iso --answer-file answer.toml --output pve-autoinstall.iso
    echo -e "${CLR_GREEN}pve-autoinstall.iso ready${CLR_RESET}"
}

# ============================================================
# INSTALL VIA QEMU
# ============================================================
is_uefi() { [ -d /sys/firmware/efi ]; }

install_proxmox() {
    echo -e "${CLR_GREEN}Starting Proxmox installation via QEMU...${CLR_RESET}"
    local uefi_opts=""
    is_uefi && uefi_opts="-bios /usr/share/ovmf/OVMF.fd" && echo "  UEFI mode"
    echo -e "${CLR_RED}Do NOT interrupt — wait ~5-10 min${CLR_RESET}"

    qemu-system-x86_64 \
        -enable-kvm $uefi_opts \
        -cpu host -smp 4 -m 4096 \
        -boot d -cdrom ./pve-autoinstall.iso \
        -drive file=${DISK1},format=raw,media=disk,if=virtio \
        -drive file=${DISK2},format=raw,media=disk,if=virtio \
        -no-reboot -display none > /dev/null 2>&1

    echo -e "${CLR_GREEN}Installation complete${CLR_RESET}"
}

# ============================================================
# POST-INSTALL CONFIGURATION VIA SSH
# ============================================================
boot_and_configure() {
    echo -e "${CLR_GREEN}Booting installed system for configuration...${CLR_RESET}"

    local uefi_opts=""
    is_uefi && uefi_opts="-bios /usr/share/ovmf/OVMF.fd"

    nohup qemu-system-x86_64 -enable-kvm $uefi_opts \
        -cpu host -device e1000,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::5555-:22 \
        -smp 4 -m 4096 \
        -drive file=${DISK1},format=raw,media=disk,if=virtio \
        -drive file=${DISK2},format=raw,media=disk,if=virtio \
        -display none > qemu_output.log 2>&1 &
    QEMU_PID=$!

    echo "  QEMU PID: $QEMU_PID"
    echo -n "  Waiting for SSH"
    for i in $(seq 1 60); do
        if nc -z localhost 5555 2>/dev/null; then
            echo -e " ${CLR_GREEN}ready${CLR_RESET}"
            break
        fi
        echo -n "."
        sleep 5
        [[ $i -eq 60 ]] && { echo -e "\n${CLR_RED}SSH timeout after 5 min${CLR_RESET}"; return 1; }
    done

    local SSH="sshpass -p $NEW_ROOT_PASSWORD ssh -p 5555 -o StrictHostKeyChecking=no root@localhost"
    local SCP="sshpass -p $NEW_ROOT_PASSWORD scp -P 5555 -o StrictHostKeyChecking=no"

    ssh-keygen -f "/root/.ssh/known_hosts" -R "[localhost]:5555" 2>/dev/null || true

    # ---- Generate and push config files ----
    echo -e "${CLR_BLUE}Configuring system...${CLR_RESET}"

    # /etc/hosts
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

    # /etc/network/interfaces
    cat > /tmp/pve-interfaces << EOF
# Network interface configuration — generated by pve-install-hetzner.sh
auto lo
iface lo inet loopback

iface ${INTERFACE_NAME} inet manual

auto vmbr0
iface vmbr0 inet static
    address ${MAIN_IPV4_CIDR}
    gateway ${MAIN_IPV4_GW}
    bridge-ports ${INTERFACE_NAME}
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

    # /etc/resolv.conf
    $SSH "printf 'search ${FQDN#*.}\nnameserver ${DNS1}\nnameserver ${DNS2}\n' > /etc/resolv.conf"

    # /etc/hostname
    $SSH "echo ${HOSTNAME} > /etc/hostname"

    # Sysctl baseline
    cat > /tmp/pve-sysctl << 'EOF'
net.netfilter.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_tcp_timeout_established=28800
EOF
    $SCP /tmp/pve-sysctl root@localhost:/etc/sysctl.d/99-proxmox.conf

    # Disable enterprise repos, enable community
    $SSH "[ -f /etc/apt/sources.list ] && mv /etc/apt/sources.list /etc/apt/sources.list.bak || true"
    $SSH "for f in /etc/apt/sources.list.d/pve-enterprise.* /etc/apt/sources.list.d/ceph*; do [ -f \"\$f\" ] && mv \"\$f\" \"\${f}.disabled\"; done || true"

    # Disable rpcbind
    $SSH "systemctl disable --now rpcbind rpcbind.socket 2>/dev/null || true"

    # Shutdown VM
    echo -e "${CLR_YELLOW}Shutting down VM...${CLR_RESET}"
    $SSH 'poweroff' || true
    wait $QEMU_PID 2>/dev/null || true
    echo -e "${CLR_GREEN}Post-configuration complete${CLR_RESET}"
}

# ============================================================
# DRY RUN
# ============================================================
dry_run_summary() {
    echo ""
    echo -e "${CLR_YELLOW}============================================${CLR_RESET}"
    echo -e "${CLR_YELLOW} DRY RUN — No changes will be made${CLR_RESET}"
    echo -e "${CLR_YELLOW}============================================${CLR_RESET}"
    echo ""
    echo "  Hostname:   ${HOSTNAME}"
    echo "  FQDN:       ${FQDN}"
    echo "  Country:    ${COUNTRY}"
    echo "  Timezone:   ${TIMEZONE}"
    echo "  Keyboard:   ${KEYBOARD}"
    echo "  Email:      ${EMAIL}"
    echo ""
    echo "  Interface:  ${INTERFACE_NAME}"
    echo "  IPv4 CIDR:  ${MAIN_IPV4_CIDR}"
    echo "  Gateway:    ${MAIN_IPV4_GW}"
    echo "  MAC:        ${MAC_ADDRESS}"
    echo "  IPv6:       ${IPV6_CIDR:-none}"
    echo "  DNS:        ${DNS1}, ${DNS2}"
    echo ""
    echo "  Filesystem: ${FILESYSTEM}"
    echo "  RAID:       ${ZFS_RAID}"
    echo "  Disk 1:     ${DISK1}"
    echo "  Disk 2:     ${DISK2}"
    echo ""
    echo "  UEFI:       $(is_uefi && echo yes || echo no)"
    echo ""
    echo "Steps that would execute:"
    echo "  1. Install packages (proxmox-auto-install-assistant, xorriso, ovmf)"
    echo "  2. Download latest Proxmox VE ISO"
    echo "  3. Generate answer.toml"
    echo "  4. Build autoinstall ISO"
    echo "  5. Install via QEMU to ${DISK1} + ${DISK2}"
    echo "  6. Boot VM, configure via SSH (hosts, interfaces, resolv.conf)"
    echo "  7. Reboot into Proxmox"
    echo ""
    echo "Post-install: run pve-harden.sh with matching TOML for security hardening"
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
    dry_run_summary
    exit 0
fi

# Confirm before proceeding (even non-interactive)
echo ""
echo -e "${CLR_RED}WARNING: This will ERASE ${DISK1} and ${DISK2}${CLR_RESET}"
if $INTERACTIVE; then
    read -p "Continue? (yes/no): " CONFIRM
    [[ "$CONFIRM" != "yes" ]] && { echo "Aborted."; exit 0; }
else
    echo -e "${CLR_YELLOW}Non-interactive mode — proceeding in 5 seconds...${CLR_RESET}"
    echo -e "${CLR_YELLOW}Press Ctrl+C to abort${CLR_RESET}"
    sleep 5
fi

prepare_packages
download_iso
make_answer_toml
make_autoinstall_iso
install_proxmox
boot_and_configure

echo ""
echo -e "${CLR_GREEN}============================================${CLR_RESET}"
echo -e "${CLR_GREEN} Installation complete!${CLR_RESET}"
echo -e "${CLR_GREEN} Access: https://${MAIN_IPV4}:8006${CLR_RESET}"
echo -e "${CLR_GREEN}============================================${CLR_RESET}"
echo ""
echo "Next steps:"
echo "  1. Reboot into Proxmox"
echo "  2. Run: bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-harden.sh) <config.toml>"
echo ""

if $SKIP_REBOOT; then
    echo -e "${CLR_YELLOW}Skipping reboot (--no-reboot)${CLR_RESET}"
else
    if $INTERACTIVE; then
        read -e -p "Reboot now? (y/n): " -i "y" DO_REBOOT
        [[ "$DO_REBOOT" == "y" ]] && reboot
    else
        echo -e "${CLR_YELLOW}Rebooting in 5 seconds...${CLR_RESET}"
        sleep 5
        reboot
    fi
fi
