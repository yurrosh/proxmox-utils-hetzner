#!/usr/bin/env bash
# vm-template.sh — Create a VM template from a Debian/Ubuntu cloud image
# Run on the Proxmox HOST.
#
# Usage:
#   bash vm-template.sh <config.toml>
#   bash vm-template.sh <config.toml> --apply
#
# Without --apply, shows what it would do (dry run).
#
# Reads [template] section from TOML config:
#   vmid, name, image_url, disk_size, storage, cores, memory,
#   cloud_init_user, cloud_init_dns, ssh_keys_url
set -euo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $1"; }
warn() { echo -e "  ${Y}!${N} $1"; }
err()  { echo -e "  ${R}✗${N} $1"; }
info() { echo -e "  ${D}·${N} $1"; }
step() { echo -e "\n${C}[$1/${TOTAL}] $2${N}"; }
TOTAL=7

usage() {
    echo "Usage: $0 <config.toml> [--apply]"
    echo ""
    echo "  config.toml   Server config with [template] section"
    echo "  --apply       Actually create template (default: dry run)"
    exit 1
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage
[ $# -lt 1 ] && usage

CONFIG="$1"
APPLY=false
[ "${2:-}" = "--apply" ] && APPLY=true

if [[ ! -f "$CONFIG" ]]; then echo -e "${R}Config not found: $CONFIG${N}"; exit 1; fi
if [[ $EUID -ne 0 ]]; then echo -e "${R}Must run as root on the Proxmox host${N}"; exit 1; fi

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

# ── Load config ─────────────────────────────────────────────────────────
VMID=$(parse_toml "$CONFIG" template vmid "9000")
TPL_NAME=$(parse_toml "$CONFIG" template name "debian-docker-tpl")
IMAGE_URL=$(parse_toml "$CONFIG" template image_url "https://cloud.debian.org/images/cloud/trixie/daily/latest/debian-13-genericcloud-amd64-daily.qcow2")
DISK_SIZE=$(parse_toml "$CONFIG" template disk_size "64G")
STORAGE=$(parse_toml "$CONFIG" template storage "local-zfs")
TPL_CORES=$(parse_toml "$CONFIG" template cores "2")
TPL_MEMORY=$(parse_toml "$CONFIG" template memory "4096")
CI_USER=$(parse_toml "$CONFIG" template cloud_init_user "root")
CI_DNS=$(parse_toml "$CONFIG" template cloud_init_dns "1.1.1.1")
SSH_KEYS_URL=$(parse_toml "$CONFIG" template ssh_keys_url "")
OPTIMIZE_SCRIPT=$(parse_toml "$CONFIG" template optimize_script "https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/vm-optimize.sh")

# NAT config for cloud-init defaults
NAT_GW=$(parse_toml "$CONFIG" nat address "10.10.10.1/24")
NAT_GW="${NAT_GW%%/*}"

echo -e "${W}vm-template.sh — Create VM template${N}"
echo -e "${D}$(date '+%Y-%m-%d %H:%M:%S %Z')${N}"

# ── Check if template exists ────────────────────────────────────────────
step 1 "Checking environment"
if qm status "$VMID" &>/dev/null; then
    warn "VM $VMID already exists"
    if qm config "$VMID" 2>/dev/null | grep -q "^template: 1"; then
        warn "It's already a template — delete first: qm destroy $VMID"
        exit 1
    else
        warn "It's a regular VM — destroy first or use a different VMID"
        exit 1
    fi
fi
ok "VMID $VMID is free"

if ! pvesm status | grep -q "^${STORAGE}"; then
    err "Storage '$STORAGE' not found"; exit 1
fi
ok "Storage: $STORAGE"

# ── Download cloud image ────────────────────────────────────────────────
step 2 "Downloading cloud image"
IMAGE_FILE="/tmp/$(basename "$IMAGE_URL")"
if [[ -f "$IMAGE_FILE" ]]; then
    info "Cached: $IMAGE_FILE"
else
    info "URL: $IMAGE_URL"
    if $APPLY; then
        wget -q --show-progress -O "$IMAGE_FILE" "$IMAGE_URL"
        ok "Downloaded $(du -h "$IMAGE_FILE" | cut -f1)"
    else
        info "(dry run — would download)"
    fi
fi

# ── Plan ────────────────────────────────────────────────────────────────
step 3 "Plan"
echo ""
echo -e "  ${W}Template:${N}"
echo -e "    VMID:      $VMID"
echo -e "    Name:      $TPL_NAME"
echo -e "    Cores:     $TPL_CORES"
echo -e "    Memory:    $TPL_MEMORY MB"
echo -e "    Disk:      $DISK_SIZE on $STORAGE"
echo -e "    Cloud-init user: $CI_USER"
echo -e "    DNS:       $CI_DNS"
echo ""

if ! $APPLY; then
    echo -e "${Y}Dry run complete. Add --apply to execute.${N}"
    exit 0
fi

# ── Create VM ───────────────────────────────────────────────────────────
step 4 "Creating VM $VMID"
qm create "$VMID" \
    --name "$TPL_NAME" \
    --ostype l26 \
    --cpu host \
    --cores "$TPL_CORES" \
    --memory "$TPL_MEMORY" \
    --balloon 0 \
    --net0 "virtio,bridge=vmbr1" \
    --scsihw virtio-scsi-single \
    --agent enabled=1,fstrim_cloned_disks=1 \
    --serial0 socket \
    --vga virtio \
    --tablet 0 \
    --bios ovmf \
    --efidisk0 "${STORAGE}:1,efitype=4m,pre-enrolled-keys=0" \
    --machine q35
ok "VM created (OVMF UEFI, virtio VGA, serial0 emergency)"

# ── Import disk ─────────────────────────────────────────────────────────
step 5 "Importing disk + cloud-init"
qm importdisk "$VMID" "$IMAGE_FILE" "$STORAGE" >/dev/null
ok "Disk imported"

# Find the imported disk (efidisk0 takes disk-0, so imported disk is typically disk-1)
IMPORTED_DISK=$(qm config "$VMID" | grep '^unused' | head -1 | sed 's/.*: //')
if [[ -z "$IMPORTED_DISK" ]]; then
    err "Could not find imported disk"; exit 1
fi
info "Imported disk: $IMPORTED_DISK"

# Attach as scsi0 with io_uring, discard, SSD, no cache (optimal for ZFS)
qm set "$VMID" --scsi0 "${IMPORTED_DISK},aio=io_uring,cache=none,iothread=1,discard=on,ssd=1"
qm resize "$VMID" scsi0 "$DISK_SIZE"
ok "Disk resized to $DISK_SIZE"

qm set "$VMID" --boot order=scsi0
qm set "$VMID" --scsi1 "${STORAGE}:cloudinit"
ok "Cloud-init drive added (scsi1)"

# Cloud-init defaults
qm set "$VMID" --ciuser "$CI_USER"
qm set "$VMID" --nameserver "$CI_DNS"
qm set "$VMID" --ipconfig0 "ip=10.10.10.10/24,gw=${NAT_GW}"

# SSH keys
if [[ -n "$SSH_KEYS_URL" ]]; then
    curl -sSfL "$SSH_KEYS_URL" > /tmp/tpl-ssh-keys.pub 2>/dev/null
    if [[ -s /tmp/tpl-ssh-keys.pub ]]; then
        qm set "$VMID" --sshkeys /tmp/tpl-ssh-keys.pub
        ok "SSH keys from $SSH_KEYS_URL"
    else
        warn "Could not fetch SSH keys — set manually"
    fi
elif [[ -f /root/.ssh/authorized_keys ]]; then
    qm set "$VMID" --sshkeys /root/.ssh/authorized_keys
    ok "SSH keys from host authorized_keys"
else
    warn "No SSH keys configured — set before cloning"
fi

ok "Cloud-init configured"

# ── Bake optimizations ──────────────────────────────────────────────────
step 6 "Baking optimizations into image"
if command -v virt-customize &>/dev/null; then
    # Download vm-optimize.sh
    OPTSCRIPT="/tmp/vm-optimize-tpl.sh"
    if [[ "$OPTIMIZE_SCRIPT" == http* ]]; then
        curl -sSfL -o "$OPTSCRIPT" "$OPTIMIZE_SCRIPT"
    elif [[ -f "$OPTIMIZE_SCRIPT" ]]; then
        cp "$OPTIMIZE_SCRIPT" "$OPTSCRIPT"
    fi

    if [[ -f "$OPTSCRIPT" ]]; then
        # Find the actual disk image (scsi0)
        SCSI0_VOL=$(qm config "$VMID" | awk '/^scsi0:/ {split($2,a,","); print a[1]}')
        DISK_PATH=$(pvesm path "$SCSI0_VOL" 2>/dev/null)
        if [[ -n "$DISK_PATH" ]]; then
            TEMPLATE_MODE=1 virt-customize -a "$DISK_PATH" \
                --install qemu-guest-agent,curl,wget,htop,iotop,jq,unzip,git,tmux,rsync,net-tools,dnsutils \
                --run "$OPTSCRIPT" \
                --run-command 'systemctl enable qemu-guest-agent' \
                --run-command 'truncate -s 0 /etc/machine-id && rm -f /var/lib/dbus/machine-id' \
                2>&1 | tail -5
            ok "Packages + optimizations baked in"
        else
            warn "Cannot find disk path — run vm-optimize.sh manually after first boot"
        fi
    else
        warn "vm-optimize.sh not found — skipping"
    fi
else
    warn "virt-customize not installed — run vm-optimize.sh manually after first boot"
fi

# ── Convert to template ─────────────────────────────────────────────────
step 7 "Converting to template"
qm template "$VMID"
ok "VM $VMID is now a template"

# ── Summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo -e "${G} ✓ Template $VMID ($TPL_NAME) ready${N}"
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${W}Clone example:${N}"
echo -e "    ${D}qm clone $VMID 101 --name prod-main --full${N}"
echo -e "    ${D}qm set 101 --memory 65536 --cores 16${N}"
echo -e "    ${D}qm resize 101 scsi0 512G${N}"
echo -e "    ${D}qm set 101 --ipconfig0 ip=10.10.10.11/24,gw=${NAT_GW}${N}"
echo -e "    ${D}qm start 101${N}"
echo ""
echo -e "  ${W}Or use:${N} bash vm-clone.sh <config.toml> --apply"
echo ""
