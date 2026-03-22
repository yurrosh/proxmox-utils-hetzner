#!/bin/bash
# =============================================================================
# pve-snap.sh — Proxmox VM snapshots with retention
#
# Usage:
#   pve-snap.sh <vmid> [keep_days]       Nightly auto-snapshot + prune
#   pve-snap.sh <vmid> --manual [desc]   Manual named snapshot (never auto-pruned)
#   pve-snap.sh <vmid> --list            List all snapshots
#   pve-snap.sh <vmid> --rollback <name> Rollback to snapshot (stops VM!)
#
# Deployment:
#   cp ops/pve-snap.sh /opt/upstaff-ops/bin/pve-snap.sh
#   chmod +x /opt/upstaff-ops/bin/pve-snap.sh
#   cp cron.d/pve-snapshots /etc/cron.d/pve-snapshots
# =============================================================================

set -euo pipefail

VMID="${1:-}"
ACTION="${2:-auto}"
KEEP_DAYS="${2:-7}"

C_RESET="\033[0m" C_BOLD="\033[1m" C_GREEN="\033[32m" C_YELLOW="\033[33m" C_RED="\033[31m" C_DIM="\033[2m"
ok()   { echo -e "  ${C_GREEN}✓${C_RESET} $*"; }
warn() { echo -e "  ${C_YELLOW}⚠${C_RESET} $*"; }
fail() { echo -e "  ${C_RED}✗${C_RESET} $*"; exit 1; }

if [[ -z "$VMID" ]]; then
    echo "Usage: pve-snap.sh <vmid> [keep_days|--manual|--list|--rollback]"
    echo ""
    echo "  pve-snap.sh 201           Auto-snapshot + prune (default 7 days)"
    echo "  pve-snap.sh 201 14        Auto-snapshot + prune (14 day retention)"
    echo "  pve-snap.sh 201 --manual \"before upgrade\"   Manual snapshot"
    echo "  pve-snap.sh 201 --list    List snapshots"
    echo "  pve-snap.sh 201 --rollback auto-20260301-0300"
    exit 1
fi

# Verify VM exists
qm status "$VMID" &>/dev/null || fail "VM $VMID not found"

case "$ACTION" in

    --list)
        echo -e "${C_BOLD}Snapshots for VM ${VMID}:${C_RESET}"
        qm listsnapshot "$VMID" 2>/dev/null | while read -r line; do
            if echo "$line" | grep -q "auto-"; then
                echo -e "  ${C_DIM}${line}${C_RESET}"
            elif echo "$line" | grep -q "manual-"; then
                echo -e "  ${C_BOLD}${line}${C_RESET}"
            else
                echo "  $line"
            fi
        done
        ;;

    --manual)
        DESC="${3:-manual snapshot}"
        TAG="manual-$(date +%Y%m%d-%H%M)"
        echo "Creating manual snapshot: ${TAG}"
        qm snapshot "$VMID" "$TAG" --description "$DESC" 2>&1 && \
            ok "Created: $TAG" || fail "Snapshot failed"
        ;;

    --rollback)
        SNAP_NAME="${3:-}"
        [[ -z "$SNAP_NAME" ]] && fail "Usage: pve-snap.sh $VMID --rollback <snapshot-name>"
        echo -e "${C_YELLOW}WARNING: This will stop VM $VMID and rollback to ${SNAP_NAME}${C_RESET}"
        echo -n "Continue? [y/N] "
        read -r confirm
        [[ "$confirm" == "y" || "$confirm" == "Y" ]] || { echo "Aborted."; exit 0; }
        qm rollback "$VMID" "$SNAP_NAME" 2>&1 && \
            ok "Rolled back to: $SNAP_NAME" || fail "Rollback failed"
        ;;

    *)
        # Auto mode — create snapshot + prune old ones
        # KEEP_DAYS is $2 if numeric, else default 7
        [[ "$KEEP_DAYS" =~ ^[0-9]+$ ]] || KEEP_DAYS=7
        TAG="auto-$(date +%Y%m%d-%H%M)"

        # Create
        echo "[$(date)] VM $VMID: creating $TAG (retention: ${KEEP_DAYS}d)"
        qm snapshot "$VMID" "$TAG" --description "nightly auto-snapshot" 2>&1 && \
            ok "Created: $TAG" || { fail "Snapshot failed"; }

        # Prune
        qm listsnapshot "$VMID" 2>/dev/null | grep " auto-" | awk '{print $2}' | while read -r snap; do
            snap_date=$(echo "$snap" | grep -oE "[0-9]{8}")
            [[ -z "$snap_date" ]] && continue
            snap_ts=$(date -d "${snap_date:0:4}-${snap_date:4:2}-${snap_date:6:2}" +%s 2>/dev/null) || continue
            cutoff_ts=$(date -d "-${KEEP_DAYS} days" +%s)
            if (( snap_ts < cutoff_ts )); then
                qm delsnapshot "$VMID" "$snap" 2>&1 && \
                    ok "Pruned: $snap" || warn "Failed to prune: $snap"
            fi
        done
        ;;
esac
