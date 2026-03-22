#!/bin/bash
# =============================================================================
# srv-sync.sh — Bi-directional rsync of /opt/upstaff-srv-shared
#
# Uses --update so newer files always win. No --delete to prevent
# accidental deletion propagation. Delete on both sides to truly remove.
#
# Usage:
#   srv-sync.sh              Sync both directions (default)
#   srv-sync.sh --push       Push local → remote only
#   srv-sync.sh --pull       Pull remote → local only
#   srv-sync.sh --dry-run    Show what would change
#   srv-sync.sh --status     Show last sync time
#
# Deployment:
#   cp ops/srv-sync.sh /opt/upstaff-ops/bin/srv-sync.sh
#   chmod +x /opt/upstaff-ops/bin/srv-sync.sh
#   mkdir -p /opt/upstaff-srv-shared /var/lib/upstaff-ops
#   cp cron.d/srv-sync-fsn /etc/cron.d/srv-sync   # on FSN
#   cp cron.d/srv-sync-hel /etc/cron.d/srv-sync   # on HEL
# =============================================================================

set -euo pipefail

SHARED="/opt/upstaff-srv-shared/"
STATE_DIR="/var/lib/upstaff-ops"
LOCK="/var/run/srv-sync.lock"
LOGFILE="/var/log/srv-sync.log"
SSH_OPTS="ssh -o ConnectTimeout=10 -o BatchMode=yes"

# Determine local/remote
HOSTNAME=$(hostname -s)
if [[ "$HOSTNAME" == "upfsn1" ]]; then
    REMOTE="root@10.99.0.2"
    LOCAL_NAME="FSN"
    REMOTE_NAME="HEL"
elif [[ "$HOSTNAME" == "uphel1" ]]; then
    REMOTE="root@10.99.0.1"
    LOCAL_NAME="HEL"
    REMOTE_NAME="FSN"
else
    echo "Unknown host: $HOSTNAME" >&2; exit 1
fi

ACTION="${1:-sync}"
DRY=""

C_RESET="\033[0m" C_GREEN="\033[32m" C_YELLOW="\033[33m" C_RED="\033[31m" C_BOLD="\033[1m"
ok()   { echo -e "  ${C_GREEN}✓${C_RESET} $*"; }
warn() { echo -e "  ${C_YELLOW}⚠${C_RESET} $*"; }
fail() { echo -e "  ${C_RED}✗${C_RESET} $*"; }
log()  { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> "$LOGFILE"; }

mkdir -p "$STATE_DIR"

case "$ACTION" in
    --dry-run)
        DRY="--dry-run"
        ACTION="sync"
        echo -e "${C_BOLD}Dry run — no changes will be made${C_RESET}"
        ;;
    --status)
        echo -e "${C_BOLD}srv-sync status:${C_RESET}"
        if [[ -f "$STATE_DIR/last-sync" ]]; then
            echo "  Last sync: $(cat "$STATE_DIR/last-sync")"
        else
            echo "  Never synced"
        fi
        if [[ -f "$LOGFILE" ]]; then
            echo "  Recent log:"
            tail -5 "$LOGFILE" | sed 's/^/    /'
        fi
        exit 0
        ;;
    --push|--pull|sync) ;;
    *) echo "Usage: srv-sync.sh [--push|--pull|--dry-run|--status]"; exit 1 ;;
esac

# Lock to prevent concurrent runs
exec 200>"$LOCK"
flock -n 200 || { warn "Another sync is running"; exit 1; }

# Test connectivity
if ! $SSH_OPTS "$REMOTE" true 2>/dev/null; then
    fail "Cannot reach $REMOTE_NAME via WireGuard"
    log "FAIL: cannot reach $REMOTE_NAME"
    exit 1
fi

do_push() {
    echo -e "${C_BOLD}→ Push: ${LOCAL_NAME} → ${REMOTE_NAME}${C_RESET}"
    rsync -avz --update --chmod=D755,F644 -e "$SSH_OPTS" $DRY "$SHARED" "${REMOTE}:${SHARED}" 2>&1 | grep -v "^$" | head -50
    if [[ -z "$DRY" ]]; then
        ok "Push complete"
        log "PUSH ${LOCAL_NAME}→${REMOTE_NAME} OK"
    fi
}

do_pull() {
    echo -e "${C_BOLD}← Pull: ${REMOTE_NAME} → ${LOCAL_NAME}${C_RESET}"
    rsync -avz --update --chmod=D755,F644 -e "$SSH_OPTS" $DRY "${REMOTE}:${SHARED}" "$SHARED" 2>&1 | grep -v "^$" | head -50
    if [[ -z "$DRY" ]]; then
        ok "Pull complete"
        log "PULL ${REMOTE_NAME}→${LOCAL_NAME} OK"
    fi
}

case "$ACTION" in
    --push) do_push ;;
    --pull) do_pull ;;
    sync)   do_pull; do_push ;;
esac

if [[ -z "$DRY" ]]; then
    date -u +%Y-%m-%dT%H:%M:%SZ > "$STATE_DIR/last-sync"
    ok "Sync complete at $(cat "$STATE_DIR/last-sync")"
fi
