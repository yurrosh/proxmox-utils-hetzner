#!/usr/bin/env bash
# vm-clone.sh — Clone a VM from template with production resources
# Run on the Proxmox HOST.
#
# Usage:
#   bash vm-clone.sh <config.toml> [--apply]
#
# Reads [vm] section from TOML config (or [vm.<name>] for multiple VMs).
set -euo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $1"; }
warn() { echo -e "  ${Y}!${N} $1"; }
err()  { echo -e "  ${R}✗${N} $1"; }
info() { echo -e "  ${D}·${N} $1"; }

usage() {
    echo "Usage: $0 <config.toml> [--apply]"
    echo ""
    echo "  Reads [vm] section from TOML for VM parameters."
    echo "  --apply    Actually create VM (default: dry run)"
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
TEMPLATE_ID=$(parse_toml "$CONFIG" template vmid "9000")
VMID=$(parse_toml "$CONFIG" vm vmid "101")
VM_NAME=$(parse_toml "$CONFIG" vm name "prod-main")
VM_MEMORY=$(parse_toml "$CONFIG" vm memory "65536")
VM_CORES=$(parse_toml "$CONFIG" vm cores "16")
VM_DISK=$(parse_toml "$CONFIG" vm disk_size "512G")
VM_IP=$(parse_toml "$CONFIG" vm ip "10.10.10.11/24")
VM_HOTPLUG=$(parse_toml "$CONFIG" vm hotplug "disk,network")
VM_BALLOON=$(parse_toml "$CONFIG" vm balloon "0")
VM_START=$(parse_toml "$CONFIG" vm start_after_clone "true")
VM_NUMA=$(parse_toml "$CONFIG" vm numa "1")
VM_KSM=$(parse_toml "$CONFIG" vm allow_ksm "0")
VM_NET_QUEUES=$(parse_toml "$CONFIG" vm net_queues "4")
VM_CIPASSWORD=$(parse_toml "$CONFIG" vm cipassword "")
VM_DISK_AIO=$(parse_toml "$CONFIG" vm disk_aio "io_uring")
VM_DISK_CACHE=$(parse_toml "$CONFIG" vm disk_cache "none")

NAT_GW=$(parse_toml "$CONFIG" nat address "10.10.10.1/24")
NAT_GW="${NAT_GW%%/*}"

echo -e "${W}vm-clone.sh — Clone VM from template${N}"
echo -e "${D}$(date '+%Y-%m-%d %H:%M:%S %Z')${N}"

# ── Validate ────────────────────────────────────────────────────────────
echo -e "\n${C}[1/4] Validating${N}"

if ! qm status "$TEMPLATE_ID" &>/dev/null; then
    err "Template $TEMPLATE_ID does not exist — run vm-template.sh first"
    exit 1
fi
if ! qm config "$TEMPLATE_ID" 2>/dev/null | grep -q "^template: 1"; then
    err "VM $TEMPLATE_ID is not a template"
    exit 1
fi
ok "Template $TEMPLATE_ID found"

if qm status "$VMID" &>/dev/null; then
    err "VM $VMID already exists — destroy first or use a different VMID"
    exit 1
fi
ok "VMID $VMID is free"

# ── Plan ────────────────────────────────────────────────────────────────
echo -e "\n${C}[2/4] Plan${N}"
echo ""
echo -e "  ${W}Clone:${N}"
echo -e "    Template:  $TEMPLATE_ID → VM $VMID ($VM_NAME)"
echo -e "    Memory:    $VM_MEMORY MB (balloon=$VM_BALLOON)"
echo -e "    Cores:     $VM_CORES (NUMA=$VM_NUMA)"
echo -e "    Disk:      $VM_DISK (aio=$VM_DISK_AIO, cache=$VM_DISK_CACHE)"
echo -e "    Net:       queues=$VM_NET_QUEUES, KSM=$VM_KSM"
echo -e "    IP:        $VM_IP (gw=$NAT_GW)"
echo -e "    Hotplug:   $VM_HOTPLUG"
echo ""

if ! $APPLY; then
    echo -e "${Y}Dry run complete. Add --apply to execute.${N}"
    exit 0
fi

# ── Clone ───────────────────────────────────────────────────────────────
echo -e "\n${C}[3/4] Cloning${N}"

qm clone "$TEMPLATE_ID" "$VMID" --name "$VM_NAME" --full
ok "Cloned $TEMPLATE_ID → $VMID ($VM_NAME)"

qm set "$VMID" \
    --memory "$VM_MEMORY" \
    --balloon "$VM_BALLOON" \
    --cores "$VM_CORES" \
    --numa "$VM_NUMA" \
    --allow-ksm "$VM_KSM" \
    --tablet 0 \
    --hotplug "$VM_HOTPLUG" \
    --ipconfig0 "ip=${VM_IP},gw=${NAT_GW}" \
    --onboot 1
ok "Resources set: ${VM_CORES} cores, ${VM_MEMORY}MB RAM, NUMA=$VM_NUMA"

# Set net0 multiqueue (improves throughput with multiple cores)
qm set "$VMID" --net0 "virtio,bridge=vmbr1,queues=${VM_NET_QUEUES}"
ok "Net0 multiqueue: queues=$VM_NET_QUEUES"

# Override scsi0 with optimal I/O settings for ZFS
SCSI0_VOL=$(qm config "$VMID" | awk '/^scsi0:/ {split($2,a,","); print a[1]}')
qm set "$VMID" --scsi0 "${SCSI0_VOL},aio=${VM_DISK_AIO},cache=${VM_DISK_CACHE},discard=on,iothread=1,ssd=1"
ok "Disk I/O: aio=$VM_DISK_AIO, cache=$VM_DISK_CACHE"

# Set cloud-init password if configured (needed for console access)
if [[ -n "$VM_CIPASSWORD" ]]; then
    qm set "$VMID" --cipassword "$VM_CIPASSWORD"
    ok "Cloud-init password set"
fi

# Resize disk
qm resize "$VMID" scsi0 "$VM_DISK"
ok "Disk resized to $VM_DISK"

# ── Start ───────────────────────────────────────────────────────────────
echo -e "\n${C}[4/4] Starting${N}"

if [[ "$VM_START" == "true" ]]; then
    qm start "$VMID"
    ok "VM $VMID started"

    # Wait for guest agent
    echo -n "  Waiting for guest agent"
    for i in $(seq 1 30); do
        if qm agent "$VMID" ping &>/dev/null 2>&1; then
            echo -e " ${G}ready${N}"
            VM_INTERNAL_IP="${VM_IP%%/*}"
            break
        fi
        echo -n "."
        sleep 5
        if [[ $i -eq 30 ]]; then
            echo ""
            warn "Guest agent timeout — VM may still be booting"
        fi
    done
else
    info "Skipping start (start_after_clone=false)"
fi

# ── Summary ─────────────────────────────────────────────────────────────
VM_INTERNAL_IP="${VM_IP%%/*}"
echo ""
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo -e "${G} ✓ VM $VMID ($VM_NAME) created${N}"
echo -e "${W}═══════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${W}Access:${N}     ssh root@${VM_INTERNAL_IP}"
echo -e "  ${W}Console:${N}    qm terminal $VMID"
echo ""
echo -e "  ${W}Next steps:${N}"
echo -e "    1. Attach public IP: bash vm-publish.sh $VMID <IP> <MAC> --apply"
echo -e "    2. Deploy containers: docker compose up -d"
echo ""
