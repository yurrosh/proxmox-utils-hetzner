#!/bin/bash
# pve-config-archive.sh — Comprehensive Proxmox configuration archiver
# Collects ALL essential configs for backup/restoration/analysis
# Usage: bash pve-config-archive.sh [output_dir]
#
# Creates: pve-config-<hostname>-<date>.tar.gz
# Contains full configs WITH credentials/secrets

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root" >&2
    exit 1
fi

HOSTNAME=$(hostname -s)
FQDN=$(hostname -f)
DATE=$(date +%Y%m%d_%H%M%S)
OUTDIR="${1:-/root}"
WORKDIR=$(mktemp -d "/tmp/pve-archive-${HOSTNAME}-XXXX")
ARCHIVE_NAME="pve-config-${HOSTNAME}-${DATE}.tar.gz"

trap 'rm -rf "$WORKDIR"' EXIT

echo "============================================"
echo " Proxmox Config Archive: $HOSTNAME"
echo " FQDN: $FQDN"
echo " Date: $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "============================================"
echo ""

collect() {
    local src="$1"
    local dst="$2"
    mkdir -p "$(dirname "${WORKDIR}/${dst}")"
    if [ -f "$src" ]; then
        cp -a "$src" "${WORKDIR}/${dst}"
        echo "  ✓ $src"
    elif [ -d "$src" ]; then
        cp -a "$src" "${WORKDIR}/${dst}"
        echo "  ✓ $src/"
    else
        echo "  ✗ $src (not found)"
    fi
}

collect_cmd() {
    local desc="$1"
    local cmd="$2"
    local dst="$3"
    mkdir -p "$(dirname "${WORKDIR}/${dst}")"
    if eval "$cmd" > "${WORKDIR}/${dst}" 2>&1; then
        echo "  ✓ $desc"
    else
        echo "  ✗ $desc (command failed)"
    fi
}

# ============================================================
# 1. SYSTEM IDENTITY
# ============================================================
echo "--- System Identity ---"
collect /etc/hostname                       system/hostname
collect /etc/hosts                          system/hosts
collect /etc/mailname                       system/mailname
collect /etc/machine-id                     system/machine-id
collect /etc/timezone                       system/timezone
collect_cmd "hostnamectl" "hostnamectl" system/hostnamectl.txt
collect_cmd "dmidecode summary" "dmidecode -t system 2>/dev/null || echo 'dmidecode not available'" system/dmidecode.txt
collect_cmd "lsb_release" "lsb_release -a 2>/dev/null || cat /etc/os-release" system/os-release.txt
collect_cmd "uname" "uname -a" system/uname.txt

# ============================================================
# 2. BOOT / EFI / GRUB
# ============================================================
echo "--- Boot / EFI / GRUB ---"
collect /etc/default/grub                   boot/grub-default
collect /etc/grub.d/                        boot/grub.d/
collect_cmd "grub.cfg" "cat /boot/grub/grub.cfg 2>/dev/null || cat /boot/efi/EFI/proxmox/grub.cfg 2>/dev/null || echo 'grub.cfg not found'" boot/grub.cfg
collect_cmd "EFI entries" "efibootmgr -v 2>/dev/null || echo 'not UEFI or efibootmgr missing'" boot/efibootmgr.txt
collect_cmd "kernel cmdline" "cat /proc/cmdline" boot/cmdline.txt
collect_cmd "initramfs modules" "cat /etc/initramfs-tools/modules 2>/dev/null || echo 'none'" boot/initramfs-modules.txt
collect /etc/modprobe.d/                    boot/modprobe.d/
collect /etc/modules                        boot/modules
collect_cmd "lsblk" "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,PARTUUID" boot/lsblk.txt
collect_cmd "blkid" "blkid" boot/blkid.txt
collect_cmd "fstab" "cat /etc/fstab" boot/fstab
collect_cmd "systemd-boot entries" "ls -la /boot/efi/EFI/ 2>/dev/null; ls -la /boot/efi/loader/entries/ 2>/dev/null || echo 'no systemd-boot'" boot/systemd-boot.txt
collect_cmd "ESP contents" "find /boot/efi -type f 2>/dev/null || echo 'no /boot/efi'" boot/esp-contents.txt

# ============================================================
# 3. NETWORK
# ============================================================
echo "--- Network ---"
collect /etc/network/interfaces             network/interfaces
collect /etc/network/interfaces.d/          network/interfaces.d/
collect /etc/resolv.conf                    network/resolv.conf
collect_cmd "ip addr" "ip -4 addr show; echo '---'; ip -6 addr show" network/ip-addr.txt
collect_cmd "ip route" "ip route show; echo '---'; ip -6 route show" network/ip-route.txt
collect_cmd "ip link" "ip -d link show" network/ip-link.txt
collect_cmd "bridge" "bridge link show 2>/dev/null || echo 'no bridges'" network/bridge.txt
collect_cmd "iptables" "iptables-save 2>/dev/null || echo 'no iptables'" network/iptables.txt
collect_cmd "ip6tables" "ip6tables-save 2>/dev/null || echo 'no ip6tables'" network/ip6tables.txt
collect /etc/sysctl.d/                      network/sysctl.d/
collect /etc/sysctl.conf                    network/sysctl.conf
collect_cmd "sysctl net" "sysctl -a 2>/dev/null | grep -E '^net\.' | sort" network/sysctl-net.txt

# ============================================================
# 4. PROXMOX CONFIGURATION
# ============================================================
echo "--- Proxmox VE ---"
collect /etc/pve/                           pve/
collect_cmd "pveversion" "pveversion -v" pve-meta/pveversion.txt
collect_cmd "pvesh cluster status" "pvesh get /cluster/status 2>/dev/null || echo 'n/a'" pve-meta/cluster-status.txt
collect_cmd "pvesh nodes" "pvesh get /nodes 2>/dev/null || echo 'n/a'" pve-meta/nodes.txt
collect_cmd "pvesh storage" "pvesh get /storage 2>/dev/null || echo 'n/a'" pve-meta/storage.txt
collect_cmd "pvesh users" "pvesh get /access/users 2>/dev/null || echo 'n/a'" pve-meta/users.txt
collect_cmd "pvesh notifications" "pvesh get /cluster/notifications/endpoints/sendmail 2>/dev/null || echo 'n/a'" pve-meta/notifications.txt
collect_cmd "subscription" "pvesubscription get 2>/dev/null || echo 'n/a'" pve-meta/subscription.txt

# ============================================================
# 5. ZFS
# ============================================================
echo "--- ZFS ---"
collect_cmd "zpool status" "zpool status -v" zfs/zpool-status.txt
collect_cmd "zpool list" "zpool list -v" zfs/zpool-list.txt
collect_cmd "zfs list" "zfs list -o all" zfs/zfs-list.txt
collect_cmd "zfs get all" "zfs get all rpool 2>/dev/null || echo 'no rpool'" zfs/zfs-get-rpool.txt
collect_cmd "zpool get all" "zpool get all rpool 2>/dev/null || echo 'no rpool'" zfs/zpool-get-rpool.txt
collect_cmd "zfs-scrub timers" "systemctl list-timers --all | grep zfs" zfs/zfs-timers.txt
collect /etc/modprobe.d/zfs.conf            zfs/modprobe-zfs.conf 2>/dev/null || true
for f in /etc/modprobe.d/*zfs*; do
    [ -f "$f" ] && collect "$f" "zfs/$(basename "$f")"
done

# ============================================================
# 6. SSH
# ============================================================
echo "--- SSH ---"
collect /etc/ssh/sshd_config                ssh/sshd_config
collect /etc/ssh/sshd_config.d/             ssh/sshd_config.d/
collect /root/.ssh/authorized_keys          ssh/authorized_keys
collect_cmd "ssh host keys list" "ls -la /etc/ssh/ssh_host_*" ssh/host-keys-list.txt
# Actual host keys (for full restore)
for f in /etc/ssh/ssh_host_*; do
    [ -f "$f" ] && collect "$f" "ssh/host-keys/$(basename "$f")"
done

# ============================================================
# 7. POSTFIX / EMAIL
# ============================================================
echo "--- Email / Postfix ---"
collect /etc/postfix/main.cf                postfix/main.cf
collect /etc/postfix/master.cf              postfix/master.cf
collect /etc/postfix/sasl_passwd            postfix/sasl_passwd
collect /etc/postfix/sasl_passwd.db         postfix/sasl_passwd.db
collect /etc/aliases                        postfix/aliases

# ============================================================
# 8. FAIL2BAN
# ============================================================
echo "--- Fail2ban ---"
collect /etc/fail2ban/jail.local            fail2ban/jail.local
collect /etc/fail2ban/jail.conf             fail2ban/jail.conf
collect /etc/fail2ban/filter.d/proxmox.conf fail2ban/filter.d/proxmox.conf
collect_cmd "fail2ban status" "fail2ban-client status 2>/dev/null || echo 'not installed'" fail2ban/status.txt

# ============================================================
# 9. FIREWALL
# ============================================================
echo "--- Firewall ---"
collect /etc/pve/firewall/                  firewall/pve-firewall/
collect_cmd "pve-firewall status" "pve-firewall status 2>/dev/null || echo 'not running'" firewall/pve-fw-status.txt
collect_cmd "nftables" "nft list ruleset 2>/dev/null || echo 'no nftables'" firewall/nftables.txt

# ============================================================
# 10. UNATTENDED UPGRADES
# ============================================================
echo "--- Unattended Upgrades ---"
collect /etc/apt/apt.conf.d/51unattended-upgrades-pve  upgrades/51unattended-upgrades-pve
collect /etc/apt/apt.conf.d/50unattended-upgrades      upgrades/50unattended-upgrades
collect /etc/apt/apt.conf.d/20auto-upgrades            upgrades/20auto-upgrades
collect_cmd "unattended status" "systemctl is-enabled unattended-upgrades 2>/dev/null || echo 'not installed'" upgrades/status.txt

# ============================================================
# 11. APT / REPOS
# ============================================================
echo "--- APT Repositories ---"
collect /etc/apt/sources.list               apt/sources.list
collect /etc/apt/sources.list.d/            apt/sources.list.d/
collect /etc/apt/trusted.gpg.d/             apt/trusted.gpg.d/
collect_cmd "apt sources" "apt-cache policy 2>/dev/null | head -50" apt/apt-policy.txt
collect_cmd "installed packages" "dpkg -l | grep -E 'proxmox|pve|fail2ban|postfix|smartmontools|unattended|libsasl'" apt/key-packages.txt

# ============================================================
# 12. SMART MONITORING
# ============================================================
echo "--- SMART / Disk Health ---"
collect /etc/smartd.conf                    smart/smartd.conf
collect_cmd "smartd status" "systemctl is-enabled smartd 2>/dev/null || echo 'not installed'" smart/status.txt
for dev in /dev/nvme?n1 /dev/sd?; do
    [ -b "$dev" ] || continue
    devname=$(basename "$dev")
    collect_cmd "SMART $devname" "smartctl -a $dev 2>/dev/null || echo 'n/a'" "smart/smartctl-${devname}.txt"
done

# ============================================================
# 13. SYSTEMD SERVICES
# ============================================================
echo "--- Systemd ---"
collect_cmd "enabled services" "systemctl list-unit-files --state=enabled --type=service" systemd/enabled-services.txt
collect_cmd "running services" "systemctl list-units --type=service --state=running" systemd/running-services.txt
collect_cmd "failed services" "systemctl --failed" systemd/failed-services.txt
collect_cmd "timers" "systemctl list-timers --all" systemd/timers.txt

# ============================================================
# 14. HARDWARE INFO
# ============================================================
echo "--- Hardware ---"
collect_cmd "lscpu" "lscpu" hardware/lscpu.txt
collect_cmd "free" "free -h" hardware/memory.txt
collect_cmd "lspci" "lspci -v 2>/dev/null || echo 'n/a'" hardware/lspci.txt
collect_cmd "lsscsi" "lsscsi 2>/dev/null || echo 'n/a'" hardware/lsscsi.txt
collect_cmd "nvme list" "nvme list 2>/dev/null || echo 'n/a'" hardware/nvme-list.txt
collect_cmd "sensors" "sensors 2>/dev/null || echo 'n/a'" hardware/sensors.txt

# ============================================================
# 15. CRON
# ============================================================
echo "--- Cron ---"
collect /etc/crontab                        cron/crontab
collect /var/spool/cron/crontabs/root       cron/root-crontab
collect /etc/cron.d/                        cron/cron.d/

# ============================================================
# CREATE MANIFEST
# ============================================================
echo ""
echo "--- Creating manifest ---"
cat > "${WORKDIR}/MANIFEST.txt" << MEOF
Proxmox Configuration Archive
==============================
Hostname:  $HOSTNAME
FQDN:      $FQDN
Date:      $(date -u '+%Y-%m-%d %H:%M:%S UTC')
PVE:       $(pveversion 2>/dev/null || echo 'unknown')
Kernel:    $(uname -r)
Archive:   $ARCHIVE_NAME

WARNING: This archive contains SECRETS and CREDENTIALS.
         Store securely. Use pve-config-sanitize.sh to
         create a safe version for external analysis.

Contents:
MEOF
find "$WORKDIR" -type f | sed "s|${WORKDIR}/||" | sort >> "${WORKDIR}/MANIFEST.txt"

# ============================================================
# COMPRESS
# ============================================================
echo "--- Compressing ---"
tar czf "${OUTDIR}/${ARCHIVE_NAME}" -C "$WORKDIR" .
chmod 600 "${OUTDIR}/${ARCHIVE_NAME}"

SIZE=$(du -sh "${OUTDIR}/${ARCHIVE_NAME}" | cut -f1)
echo ""
echo "============================================"
echo " Archive created: ${OUTDIR}/${ARCHIVE_NAME}"
echo " Size: $SIZE"
echo " ⚠ Contains secrets — store securely!"
echo "============================================"
