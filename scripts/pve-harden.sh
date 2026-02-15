#!/bin/bash
# pve-harden.sh — Post-install Proxmox VE hardening
# Applies complete security configuration for Hetzner dedicated servers
#
# Usage: bash pve-harden.sh <config.toml>
#        bash pve-harden.sh --defaults   (uses safe defaults, prompts for emails)
#        bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-harden.sh) config.toml
# Repo:  https://github.com/yurrosh/proxmox-utils-hetzner

set -euo pipefail

# When run via curl pipe, redirect interactive reads from /dev/tty
if ! [ -t 0 ]; then exec 0</dev/tty; fi

CLR_RED="\033[1;31m"
CLR_GREEN="\033[1;32m"
CLR_YELLOW="\033[1;33m"
CLR_BLUE="\033[1;34m"
CLR_RESET="\033[m"

if [[ $EUID -ne 0 ]]; then echo -e "${CLR_RED}Must run as root${CLR_RESET}"; exit 1; fi
if [[ $# -lt 1 ]]; then echo "Usage: $0 <config.toml>  or  $0 --defaults"; exit 1; fi

# ---- Minimal TOML parser ----
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
CONFIG="$1"
if [[ "$CONFIG" == "--defaults" ]]; then
    SMTP_RELAY="[smtp-relay.brevo.com]:587"; SMTP_USER=""; SMTP_KEY=""
    NOTIF_FROM=""; NOTIF_EMAIL=""
    NOTIF_AUTHOR="Proxmox $(hostname -s)"
    ZFS_ARC_MIN_GB=6; ZFS_ARC_MAX_GB=12
    CONNTRACK_MAX=1048576; CONNTRACK_TIMEOUT=28800
    PERMIT_ROOT_LOGIN="prohibit-password"
    SMART_WARN_TEMP=50; SMART_CRIT_TEMP=70
    FW_TCP_PORTS="[22, 8006]"; FW_ALLOW_ICMP="true"; FW_DEFAULT_IN="DROP"
    F2B_BANTIME=3600; F2B_FINDTIME=600; F2B_MAXRETRY=3
    read -p "SMTP user (from-address for Brevo): " SMTP_USER
    read -p "Admin email (notifications go here): " NOTIF_EMAIL
    NOTIF_FROM="${SMTP_USER}"
    echo -e "${CLR_YELLOW}Using defaults (SMTP key not set — configure manually or pass config.toml)${CLR_RESET}"
else
    if [[ ! -f "$CONFIG" ]]; then echo -e "${CLR_RED}Not found: $CONFIG${CLR_RESET}"; exit 1; fi
    SMTP_RELAY=$(parse_toml "$CONFIG" hardening smtp_relay_host "[smtp-relay.brevo.com]:587")
    SMTP_USER=$(parse_toml "$CONFIG" hardening smtp_user "")
    SMTP_KEY=$(parse_toml "$CONFIG" hardening smtp_key "")
    NOTIF_FROM=$(parse_toml "$CONFIG" hardening notification_from "${SMTP_USER}")
    NOTIF_EMAIL=$(parse_toml "$CONFIG" hardening notification_email "")
    NOTIF_AUTHOR=$(parse_toml "$CONFIG" hardening notification_author "Proxmox $(hostname -s)")
    ZFS_ARC_MIN_GB=$(parse_toml "$CONFIG" hardening zfs_arc_min_gb 6)
    ZFS_ARC_MAX_GB=$(parse_toml "$CONFIG" hardening zfs_arc_max_gb 12)
    CONNTRACK_MAX=$(parse_toml "$CONFIG" hardening conntrack_max 1048576)
    CONNTRACK_TIMEOUT=$(parse_toml "$CONFIG" hardening conntrack_tcp_timeout 28800)
    PERMIT_ROOT_LOGIN=$(parse_toml "$CONFIG" hardening permit_root_login "prohibit-password")
    SMART_WARN_TEMP=$(parse_toml "$CONFIG" hardening smart_warn_temp 50)
    SMART_CRIT_TEMP=$(parse_toml "$CONFIG" hardening smart_crit_temp 70)
    FW_TCP_PORTS=$(parse_toml "$CONFIG" hardening firewall_tcp_ports "[22, 8006]")
    FW_ALLOW_ICMP=$(parse_toml "$CONFIG" hardening firewall_allow_icmp "true")
    FW_DEFAULT_IN=$(parse_toml "$CONFIG" hardening firewall_default_in "DROP")
    F2B_BANTIME=$(parse_toml "$CONFIG" hardening f2b_bantime 3600)
    F2B_FINDTIME=$(parse_toml "$CONFIG" hardening f2b_findtime 600)
    F2B_MAXRETRY=$(parse_toml "$CONFIG" hardening f2b_maxretry 3)
fi

if [[ -z "$SMTP_USER" ]]; then echo -e "${CLR_RED}smtp_user is required (from-address for SMTP relay)${CLR_RESET}"; exit 1; fi
if [[ -z "$NOTIF_EMAIL" ]]; then echo -e "${CLR_RED}notification_email is required (where alerts go)${CLR_RESET}"; exit 1; fi

HOST_S=$(hostname -s)
FQDN=$(hostname -f)
TOTAL_STEPS=13

echo ""
echo -e "${CLR_GREEN}======= Proxmox Hardening: ${HOST_S} (${FQDN}) =======${CLR_RESET}"
echo ""

step() { echo -e "${CLR_BLUE}[$1/${TOTAL_STEPS}] $2${CLR_RESET}"; }
ok()   { echo -e "  ${CLR_GREEN}✓ $1${CLR_RESET}"; }
skip() { echo -e "  ${CLR_YELLOW}⊘ $1${CLR_RESET}"; }
warn() { echo -e "  ${CLR_YELLOW}⚠ $1${CLR_RESET}"; }

# ===========================================================
# 1. System update
# ===========================================================
step 1 "System update"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get -y dist-upgrade >/dev/null 2>&1
ok "Packages updated (dist-upgrade)"
pveam update 2>/dev/null && ok "Appliance templates updated" || true

# ===========================================================
# 2. Essential packages
# ===========================================================
step 2 "Essential packages"
PKGS="curl wget libguestfs-tools unzip net-tools fail2ban smartmontools"
PKGS="$PKGS libsasl2-modules unattended-upgrades at iptables-persistent"
# Pre-seed debconf to prevent interactive prompts (iptables-persistent, postfix, etc.)
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt-get install -yq $PKGS >/dev/null 2>&1
ok "Installed: fail2ban, smartmontools, libguestfs-tools, at, ..."

# ===========================================================
# 3. SSH hardening
# ===========================================================
step 3 "SSH hardening"
if grep -q "^PermitRootLogin ${PERMIT_ROOT_LOGIN}" /etc/ssh/sshd_config; then
    skip "Already hardened"
else
    sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin ${PERMIT_ROOT_LOGIN}/" /etc/ssh/sshd_config
    systemctl restart sshd
    ok "PermitRootLogin → ${PERMIT_ROOT_LOGIN}"
fi

# ===========================================================
# 4. APT repos — disable enterprise, enable community
# ===========================================================
step 4 "APT repositories"
for f in /etc/apt/sources.list.d/pve-enterprise.{list,sources} /etc/apt/sources.list.d/ceph*.{list,sources}; do
    [[ -f "$f" ]] && ! echo "$f" | grep -q disabled && mv "$f" "${f}.disabled" && ok "Disabled $(basename $f)"
done
if ! grep -rq "pve-no-subscription" /etc/apt/sources.list.d/ 2>/dev/null; then
    # Detect suite (bookworm/trixie) from existing repos
    SUITE=$(grep -rh "Suites:" /etc/apt/sources.list.d/ 2>/dev/null | head -1 | awk '{print $2}')
    SUITE="${SUITE:-bookworm}"
    cat > /etc/apt/sources.list.d/pve-no-subscription.sources << EOF
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: ${SUITE}
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
    ok "Added pve-no-subscription (${SUITE})"
else
    skip "pve-no-subscription exists"
fi

# ===========================================================
# 5. ZFS tuning — ARC limits, scrub, initramfs
# ===========================================================
step 5 "ZFS tuning"
# Monthly scrub
systemctl enable --now zfs-scrub-monthly@rpool.timer 2>/dev/null && ok "Monthly scrub enabled" || skip "Scrub timer already active"

# ARC limits — both min and max
ARC_MIN=$((ZFS_ARC_MIN_GB * 1024 * 1024 * 1024))
ARC_MAX=$((ZFS_ARC_MAX_GB * 1024 * 1024 * 1024))
INITRAMFS_NEEDED=false

# Remove old single-line config if present
[[ -f /etc/modprobe.d/zfs.conf ]] && grep -q "zfs_arc_max" /etc/modprobe.d/zfs.conf && \
    rm -f /etc/modprobe.d/zfs.conf && ok "Removed old /etc/modprobe.d/zfs.conf"

if [[ ! -f /etc/modprobe.d/99-zfs.conf ]] || ! grep -q "zfs_arc_min" /etc/modprobe.d/99-zfs.conf; then
    printf "options zfs zfs_arc_min=%s\noptions zfs zfs_arc_max=%s\n" "$ARC_MIN" "$ARC_MAX" > /etc/modprobe.d/99-zfs.conf
    INITRAMFS_NEEDED=true
    ok "ARC limits: ${ZFS_ARC_MIN_GB}G min / ${ZFS_ARC_MAX_GB}G max"
else
    skip "ARC already configured"
fi

# ZFS pool upgrade if features pending
if zpool status rpool 2>/dev/null | grep -q "features are not enabled"; then
    zpool upgrade rpool 2>/dev/null
    ok "ZFS pool features upgraded"
fi

# Rebuild initramfs if modprobe changed
if $INITRAMFS_NEEDED; then
    update-initramfs -u -k all >/dev/null 2>&1
    ok "initramfs rebuilt"
fi

# ===========================================================
# 6. SMART monitoring
# ===========================================================
step 6 "SMART monitoring"
if ! grep -q "W 4,${SMART_WARN_TEMP},${SMART_CRIT_TEMP}" /etc/smartd.conf 2>/dev/null; then
    # Replace all DEVICESCAN lines with one correct one
    sed -i '/^DEVICESCAN/d' /etc/smartd.conf
    # Insert after the last comment block
    sed -i "17a DEVICESCAN -a -o on -S on -n standby,q -s (S/../01/.|L/../15/3) -W 4,${SMART_WARN_TEMP},${SMART_CRIT_TEMP} -m root" /etc/smartd.conf
    systemctl restart smartd
    ok "Monthly short, quarterly long, warn@${SMART_WARN_TEMP}°C crit@${SMART_CRIT_TEMP}°C"
else
    # Clean up duplicate DEVICESCAN lines if present
    if [ "$(grep -c '^DEVICESCAN' /etc/smartd.conf)" -gt 1 ]; then
        awk '/^DEVICESCAN/{n++; if(n>1) $0 = "#" $0} {print}' /etc/smartd.conf > /tmp/smartd.conf.fixed
        cp /tmp/smartd.conf.fixed /etc/smartd.conf; rm -f /tmp/smartd.conf.fixed
        systemctl restart smartd
        ok "Cleaned duplicate DEVICESCAN lines"
    else
        skip "Already configured"
    fi
fi

# ===========================================================
# 7. Postfix SMTP relay
# ===========================================================
step 7 "Postfix SMTP relay"
echo "$FQDN" > /etc/mailname
if ! grep -q smtp_sasl_auth_enable /etc/postfix/main.cf 2>/dev/null; then
    # Remove empty relayhost line if present
    sed -i '/^relayhost\s*=\s*$/d' /etc/postfix/main.cf
    cat >> /etc/postfix/main.cf << EOF
relayhost = ${SMTP_RELAY}
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
EOF
    ok "Relay: ${SMTP_RELAY}"
else
    skip "Relay already configured"
fi

if [[ -n "$SMTP_KEY" ]]; then
    echo "${SMTP_RELAY} ${SMTP_USER}:${SMTP_KEY}" > /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd; postmap /etc/postfix/sasl_passwd
    ok "SASL credentials set"
else
    warn "No SMTP key — set manually: echo '${SMTP_RELAY} ${SMTP_USER}:YOUR_KEY' > /etc/postfix/sasl_passwd && postmap /etc/postfix/sasl_passwd"
fi
systemctl restart postfix

# PVE notification routing
pvesh set /cluster/notifications/endpoints/sendmail/mail-to-root \
    -from-address "$NOTIF_FROM" -author "$NOTIF_AUTHOR" 2>/dev/null || true
pvesh set /access/users/root@pam -email "$NOTIF_EMAIL" 2>/dev/null || true
ok "Notifications: ${NOTIF_AUTHOR} → ${NOTIF_EMAIL}"

# ===========================================================
# 8. Fail2ban
# ===========================================================
step 8 "Fail2ban"
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = ${F2B_BANTIME}
findtime = ${F2B_FINDTIME}
maxretry = ${F2B_MAXRETRY}

[sshd]
enabled = true

[proxmox]
enabled = true
port = https,http,8006
filter = proxmox
backend = systemd
maxretry = ${F2B_MAXRETRY}
findtime = ${F2B_FINDTIME}
bantime = ${F2B_BANTIME}
EOF
cat > /etc/fail2ban/filter.d/proxmox.conf << 'EOF'
[Definition]
failregex = pvedaemon\[.*authentication (verification )?failure; rhost=<HOST> user=\S+ msg=.*
ignoreregex =
journalmatch = _SYSTEMD_UNIT=pvedaemon.service
EOF
systemctl enable fail2ban; systemctl restart fail2ban; sleep 2
ok "SSH + Proxmox jails active"

# ===========================================================
# 9. Firewall — DROP all except SSH, WebUI, ICMP
# ===========================================================
step 9 "Proxmox firewall"
mkdir -p /etc/pve/firewall "/etc/pve/nodes/${HOST_S}"

# Parse TCP ports from TOML array format [22, 8006] → individual rules
FW_PORTS_CLEAN=$(echo "$FW_TCP_PORTS" | tr -d '[]' | tr ',' ' ' | xargs)

{
    echo "[OPTIONS]"
    echo "enable: 1"
    echo "policy_in: ${FW_DEFAULT_IN}"
    echo "policy_out: ACCEPT"
    echo ""
    echo "[RULES]"
    for port in $FW_PORTS_CLEAN; do
        port=$(echo "$port" | tr -d ' ')
        echo "IN ACCEPT -p tcp -dport ${port} -log nolog"
    done
    if [[ "$FW_ALLOW_ICMP" == "true" ]]; then
        echo "IN ACCEPT -p icmp -log nolog"
    fi
} > /etc/pve/firewall/cluster.fw

cat > "/etc/pve/nodes/${HOST_S}/host.fw" << 'EOF'
[OPTIONS]
enable: 1
EOF

# Safety net — auto-disable firewall in 10 minutes
echo "pve-firewall stop; sed -i 's/enable: 1/enable: 0/' /etc/pve/firewall/cluster.fw" | at now + 10 minutes 2>/dev/null
AT_JOB=$(atq | tail -1 | awk '{print $1}')
warn "Safety: firewall auto-disables in 10min → cancel with: atrm ${AT_JOB}"
systemctl restart pve-firewall
ok "${FW_DEFAULT_IN} default, allow TCP(${FW_PORTS_CLEAN// /,})$( [[ "$FW_ALLOW_ICMP" == "true" ]] && echo ' + ICMP' )"

# ===========================================================
# 10. Unattended upgrades
# ===========================================================
step 10 "Unattended upgrades"
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/51unattended-upgrades-pve << 'EOF'
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Proxmox,codename=${distro_codename}";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1
ok "Debian-Security + Proxmox, no auto-reboot"

# ===========================================================
# 11. Subscription nag removal
# ===========================================================
step 11 "Subscription nag"
PL="/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"
if [[ -f "$PL" ]] && grep -q "No valid sub" "$PL"; then
    sed -Ezi.bak "s/(Ext\.Msg\.show\(\{\s+title: gettext\('No valid sub)/void\(\{ \/\/\1/g" "$PL"
    systemctl restart pveproxy
    ok "Removed (reapply after pve-manager updates)"
else skip "Already removed or not applicable"; fi

# ===========================================================
# 12. Sysctl — conntrack tuning
# ===========================================================
step 12 "Sysctl tuning"
# Ensure nf_conntrack module loads at boot
if ! grep -q "^nf_conntrack" /etc/modules 2>/dev/null; then
    echo "nf_conntrack" >> /etc/modules
    ok "nf_conntrack added to /etc/modules"
fi
modprobe nf_conntrack 2>/dev/null || true

cat > /etc/sysctl.d/99-pve-hardening.conf << EOF
# Proxmox hardening — conntrack tuning
net.netfilter.nf_conntrack_max = ${CONNTRACK_MAX}
net.netfilter.nf_conntrack_tcp_timeout_established = ${CONNTRACK_TIMEOUT}
EOF
sysctl -p /etc/sysctl.d/99-pve-hardening.conf >/dev/null 2>&1
ok "conntrack max=${CONNTRACK_MAX}, timeout=${CONNTRACK_TIMEOUT}s"

# ===========================================================
# 13. Disable rpcbind
# ===========================================================
step 13 "Disable rpcbind"
if systemctl is-active rpcbind &>/dev/null || systemctl is-enabled rpcbind &>/dev/null; then
    systemctl disable --now rpcbind.socket rpcbind.service 2>/dev/null || true
    systemctl mask rpcbind.socket rpcbind.service 2>/dev/null || true
    ok "Disabled + masked"
else skip "Already disabled"; fi

# ===========================================================
# Summary
# ===========================================================
echo ""
echo -e "${CLR_GREEN}============================================${CLR_RESET}"
echo -e "${CLR_GREEN} Hardening complete: ${HOST_S} (${FQDN})${CLR_RESET}"
echo -e "${CLR_GREEN}============================================${CLR_RESET}"
echo ""
echo -e "${CLR_RED}⚠ IMPORTANT: Test SSH in another terminal NOW!${CLR_RESET}"
echo -e "${CLR_RED}  Then cancel the firewall safety timer: atrm ${AT_JOB}${CLR_RESET}"
echo ""
echo "Verify email works:"
echo "  echo 'Hardening complete' | mail -s '${HOST_S} hardened' ${NOTIF_EMAIL}"
echo ""
echo "Backup config:"
echo "  bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-config-archive.sh) /root"
