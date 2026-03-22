#!/bin/bash
# =============================================================================
# install.sh — Install proxmox-utils-hetzner scripts via symlinks
#
# Creates symlinks in /usr/local/bin with `up-` prefix.
# Detects context (Proxmox host vs guest VM) and installs relevant scripts.
#
# Usage:
#   ./install.sh              Install (auto-detect host vs guest)
#   ./install.sh --host       Install host scripts only
#   ./install.sh --guest      Install guest scripts only
#   ./install.sh --all        Install everything
#   ./install.sh --remove     Remove all symlinks
#   ./install.sh --status     Show installed symlinks
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
BIN_DIR="/usr/local/bin"
PREFIX="up"

C_RESET="\033[0m" C_BOLD="\033[1m" C_GREEN="\033[32m" C_YELLOW="\033[33m" C_RED="\033[31m" C_DIM="\033[2m"
ok()   { echo -e "  ${C_GREEN}✓${C_RESET} $*"; }
warn() { echo -e "  ${C_YELLOW}⚠${C_RESET} $*"; }
fail() { echo -e "  ${C_RED}✗${C_RESET} $*"; }
info() { echo -e "  ${C_DIM}$*${C_RESET}"; }

# ── Script → symlink mapping ────────────────────────────────────────────────
# Format: "source_path:symlink_name:context"
# context: host = Proxmox host, guest = inside VM, both = either

SCRIPTS=(
    # Operational scripts (ops/)
    "ops/pve-snap.sh:${PREFIX}-snap:host"
    "ops/srv-sync.sh:${PREFIX}-sync:host"

    # Host setup scripts (scripts/)
    "scripts/pve-harden.sh:${PREFIX}-harden:host"
    "scripts/pve-network.sh:${PREFIX}-network:host"
    "scripts/pve-tunnel.sh:${PREFIX}-tunnel:host"
    "scripts/pve-tune.sh:${PREFIX}-tune:host"
    "scripts/pve-config-archive.sh:${PREFIX}-config-archive:host"
    "scripts/pve-config-sanitize.sh:${PREFIX}-config-sanitize:host"
    "scripts/vm-template.sh:${PREFIX}-vm-template:host"
    "scripts/vm-clone.sh:${PREFIX}-vm-clone:host"
    "scripts/vm-publish.sh:${PREFIX}-vm-publish:host"
    "scripts/netbench.sh:${PREFIX}-netbench:both"

    # Guest scripts (scripts/ + guest-utils/)
    "scripts/vm-audit.sh:${PREFIX}-audit:guest"
    "scripts/vm-optimize.sh:${PREFIX}-optimize:guest"
    "guest-utils/docker-setup.sh:${PREFIX}-docker-setup:guest"
    "guest-utils/create-users.sh:${PREFIX}-create-users:guest"
)

# ── Detect context ───────────────────────────────────────────────────────────

detect_context() {
    if command -v pveversion &>/dev/null; then
        echo "host"
    elif [[ -f /etc/pve/.version ]]; then
        echo "host"
    else
        echo "guest"
    fi
}

# ── Install ──────────────────────────────────────────────────────────────────

do_install() {
    local filter="$1"
    local installed=0
    local skipped=0

    echo -e "${C_BOLD}Installing proxmox-utils-hetzner scripts (${PREFIX}-* → ${BIN_DIR})${C_RESET}"
    echo -e "${C_DIM}Repo: ${REPO_ROOT}${C_RESET}"
    echo -e "${C_DIM}Context filter: ${filter}${C_RESET}"
    echo ""

    for entry in "${SCRIPTS[@]}"; do
        IFS=':' read -r src name ctx <<< "$entry"
        local src_path="${REPO_ROOT}/${src}"

        # Filter by context
        if [[ "$filter" != "all" && "$ctx" != "both" && "$ctx" != "$filter" ]]; then
            continue
        fi

        # Check source exists
        if [[ ! -f "$src_path" ]]; then
            warn "${name} — source not found: ${src}"
            ((skipped++))
            continue
        fi

        # Ensure source is executable
        chmod +x "$src_path"

        # Create or update symlink
        local link_path="${BIN_DIR}/${name}"
        if [[ -L "$link_path" ]]; then
            local existing
            existing=$(readlink -f "$link_path")
            if [[ "$existing" == "$src_path" ]]; then
                info "${name} — already linked"
                ((installed++))
                continue
            fi
            # Different target — update
            ln -sf "$src_path" "$link_path"
            ok "${name} — updated (was: ${existing})"
        elif [[ -e "$link_path" ]]; then
            warn "${name} — ${link_path} exists and is not a symlink, skipping"
            ((skipped++))
            continue
        else
            ln -s "$src_path" "$link_path"
            ok "${name} — linked"
        fi
        ((installed++))
    done

    echo ""
    echo -e "${C_BOLD}Done:${C_RESET} ${installed} installed, ${skipped} skipped"

    # Also create the ops directory on the server if needed
    if [[ "$filter" == "host" || "$filter" == "all" ]]; then
        mkdir -p /opt/upstaff-ops/bin 2>/dev/null || true
    fi
}

# ── Remove ───────────────────────────────────────────────────────────────────

do_remove() {
    local removed=0

    echo -e "${C_BOLD}Removing proxmox-utils-hetzner symlinks from ${BIN_DIR}${C_RESET}"
    echo ""

    for entry in "${SCRIPTS[@]}"; do
        IFS=':' read -r src name ctx <<< "$entry"
        local link_path="${BIN_DIR}/${name}"

        if [[ -L "$link_path" ]]; then
            local target
            target=$(readlink -f "$link_path")
            # Only remove if it points into our repo
            if [[ "$target" == "${REPO_ROOT}/"* ]]; then
                rm "$link_path"
                ok "${name} — removed"
                ((removed++))
            else
                warn "${name} — points outside repo (${target}), skipping"
            fi
        fi
    done

    echo ""
    echo -e "${C_BOLD}Done:${C_RESET} ${removed} removed"
}

# ── Status ───────────────────────────────────────────────────────────────────

do_status() {
    echo -e "${C_BOLD}proxmox-utils-hetzner symlink status${C_RESET}"
    echo -e "${C_DIM}Repo: ${REPO_ROOT}${C_RESET}"
    echo ""

    printf "  %-24s %-10s %s\n" "COMMAND" "CONTEXT" "STATUS"
    printf "  %-24s %-10s %s\n" "-------" "-------" "------"

    for entry in "${SCRIPTS[@]}"; do
        IFS=':' read -r src name ctx <<< "$entry"
        local link_path="${BIN_DIR}/${name}"
        local src_path="${REPO_ROOT}/${src}"
        local status

        if [[ -L "$link_path" ]]; then
            local target
            target=$(readlink -f "$link_path")
            if [[ "$target" == "$src_path" ]]; then
                status="${C_GREEN}installed${C_RESET}"
            else
                status="${C_YELLOW}wrong target${C_RESET}"
            fi
        elif [[ -e "$link_path" ]]; then
            status="${C_YELLOW}file exists (not symlink)${C_RESET}"
        else
            if [[ -f "$src_path" ]]; then
                status="${C_DIM}not installed${C_RESET}"
            else
                status="${C_RED}source missing${C_RESET}"
            fi
        fi

        printf "  %-24s %-10s " "$name" "$ctx"
        echo -e "$status"
    done
}

# ── Main ─────────────────────────────────────────────────────────────────────

ACTION="${1:-auto}"

case "$ACTION" in
    --host)
        do_install "host"
        ;;
    --guest)
        do_install "guest"
        ;;
    --all)
        do_install "all"
        ;;
    --remove|--uninstall)
        do_remove
        ;;
    --status)
        do_status
        ;;
    --help|-h)
        head -12 "${BASH_SOURCE[0]}" | grep -E "^#[^!]" | sed 's/^# \?//'
        ;;
    auto|"")
        CONTEXT=$(detect_context)
        echo -e "${C_DIM}Auto-detected context: ${CONTEXT}${C_RESET}"
        do_install "$CONTEXT"
        ;;
    *)
        echo "Unknown option: $ACTION"
        echo "Usage: install.sh [--host|--guest|--all|--remove|--status]"
        exit 1
        ;;
esac
