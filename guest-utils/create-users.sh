#!/usr/bin/env bash
# create-users.sh — Create users with matching UIDs/GIDs + random passwords
# Run inside VM as root.
set -euo pipefail

[ "$(id -u)" -ne 0 ] && { echo "Must run as root"; exit 1; }

PASSFILE="/root/user-passwords-$(date +%Y%m%d).txt"
echo "# Generated $(date '+%Y-%m-%d %H:%M:%S %Z')" > "$PASSFILE"
chmod 600 "$PASSFILE"

create_user() {
    local user="$1" uid="$2" gecos="${3:-}" shell="${4:-/bin/bash}"
    local pass
    pass=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)

    groupadd -g "$uid" "$user" 2>/dev/null || true
    useradd -m -u "$uid" -g "$uid" -s "$shell" -c "$gecos" "$user" 2>/dev/null || true
    echo "${user}:${pass}" | chpasswd
    echo "${user}:${pass}" >> "$PASSFILE"
    echo "  ✓ ${user} (uid=${uid}, shell=${shell})"
}

echo "Creating users..."
create_user upstaff 1000 ""               /bin/bash
create_user yurrosh 1001 ""               /bin/bash
create_user kt      1002 ""               /bin/bash
create_user yurro   1003 ""               /bin/sh
create_user kindiy  1004 "Denys Kindiy"   /bin/bash
create_user upstage 1005 ""               /bin/bash

echo ""
echo "  ✓ Passwords saved to: ${PASSFILE}"
echo "  ⚠ Retrieve and delete: cat ${PASSFILE}"
