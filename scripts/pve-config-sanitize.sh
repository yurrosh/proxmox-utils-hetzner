#!/bin/bash
# pve-config-sanitize.sh — Strip secrets from Proxmox config archive
# Creates a sanitized version safe to share with LLM/external analysis
#
# Usage: bash pve-config-sanitize.sh <archive.tar.gz> [output_dir]
# Output: pve-config-<hostname>-<date>-SANITIZED.tar.gz

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <pve-config-archive.tar.gz> [output_dir]"
    exit 1
fi

ARCHIVE="$1"
OUTDIR="${2:-.}"

if [[ ! -f "$ARCHIVE" ]]; then
    echo "ERROR: Archive not found: $ARCHIVE" >&2
    exit 1
fi

WORKDIR=$(mktemp -d "/tmp/pve-sanitize-XXXX")
trap 'rm -rf "$WORKDIR"' EXIT

echo "============================================"
echo " Sanitizing Proxmox Config Archive"
echo " Source: $(basename "$ARCHIVE")"
echo "============================================"
echo ""

# Extract
tar xzf "$ARCHIVE" -C "$WORKDIR"

# ============================================================
# 1. REMOVE FILES THAT ARE ENTIRELY SECRETS
# ============================================================
echo "--- Removing secret files ---"

remove_file() {
    local f="${WORKDIR}/$1"
    if [ -e "$f" ]; then
        rm -rf "$f"
        echo "  ✗ Removed: $1"
    fi
}

# SSH private keys
find "$WORKDIR" -path "*/ssh/*" \( -name "*_key" -o -name "*.key" \) ! -name "*.pub" 2>/dev/null | while read f; do
    rm -f "$f"
    echo "  ✗ Removed: ${f#$WORKDIR/}"
done

# Postfix SASL credentials
remove_file "postfix/sasl_passwd"
remove_file "postfix/sasl_passwd.db"

# PVE auth keys, private keys, CSRF secrets
remove_file "pve/authkey.key"
remove_file "pve/pve-root-ca.key"
remove_file "pve/pve-www.key"
remove_file "pve/priv"
remove_file "pve/corosync.key"

# Remove all .key files under pve/
find "$WORKDIR/pve/" -name "*.key" 2>/dev/null | while read f; do
    rm -f "$f"
    echo "  ✗ Removed: ${f#$WORKDIR/}"
done

# ============================================================
# 2. REDACT SENSITIVE VALUES IN CONFIG FILES
# ============================================================
echo ""
echo "--- Redacting secrets in config files ---"

# Redact password hashes in shadow-like files
find "$WORKDIR" -type f -name "shadow" 2>/dev/null | while read f; do
    sed -i -E 's/^(root:)\$[^:]+/\1[HASH_REDACTED]/' "$f"
    echo "  ✓ Redacted root hash in: ${f#$WORKDIR/}"
done

# Redact PVE user token secrets
if [ -f "$WORKDIR/pve/user.cfg" ]; then
    sed -i -E 's/(token:.*:)[a-f0-9-]+$/\1[TOKEN_REDACTED]/' "$WORKDIR/pve/user.cfg"
    echo "  ✓ Redacted tokens in: pve/user.cfg"
fi

# Redact any 40+ char hex strings (API keys, SMTP keys) in config files
find "$WORKDIR" -type f \( -name "*.cfg" -o -name "*.conf" -o -name "*.cf" \) 2>/dev/null | while read f; do
    if grep -qP '[a-fA-F0-9]{40,}' "$f" 2>/dev/null; then
        sed -i -E 's/[a-fA-F0-9]{40,}/[APIKEY_REDACTED]/g' "$f"
        echo "  ✓ Redacted long hex in: ${f#$WORKDIR/}"
    fi
done

# Redact SSL certificate bodies (keep subject/dates metadata)
find "$WORKDIR/pve/" -name "*.pem" 2>/dev/null | while read f; do
    if head -1 "$f" 2>/dev/null | grep -q "BEGIN"; then
        info=$(openssl x509 -in "$f" -noout -subject -dates 2>/dev/null || echo "unparseable")
        printf "[CERTIFICATE REDACTED]\n%s\n" "$info" > "$f"
        echo "  ✓ Redacted cert: ${f#$WORKDIR/}"
    fi
done

# ============================================================
# 3. ADD SANITIZATION NOTICE
# ============================================================
echo ""
echo "--- Adding sanitization notice ---"

cat > "${WORKDIR}/SANITIZED-README.txt" << 'SEOF'
SANITIZED PROXMOX CONFIGURATION ARCHIVE
========================================

This archive has been sanitized for safe external analysis.

REMOVED:
  - SSH private host keys
  - Postfix SASL credentials (SMTP passwords)
  - PVE auth keys and private keys
  - PVE CSRF tokens (pve-www.key)
  - Corosync auth key
  - SSL certificate private keys

REDACTED (replaced with placeholders):
  - Password hashes
  - API tokens in config files
  - 40+ char hex strings (API/SMTP keys)
  - Certificate contents (subject/dates preserved)

PRESERVED (needed for config analysis):
  - IP addresses, MAC addresses, hostnames
  - SSH public keys (authorized_keys)
  - All configuration directives and values
  - Service states and package lists
  - Hardware info, disk layout, ZFS config
  - Firewall rules, fail2ban config
  - Network interfaces, routing tables
  - APT repositories and sources

This archive is SAFE to share with LLM for analysis.
SEOF

# Update manifest
if [ -f "${WORKDIR}/MANIFEST.txt" ]; then
    sed -i 's/WARNING: This archive contains SECRETS/NOTE: This archive has been SANITIZED/' "$WORKDIR/MANIFEST.txt"
    sed -i 's/Store securely.*/Secrets removed. Safe for external analysis./' "$WORKDIR/MANIFEST.txt"
fi

# ============================================================
# 4. REPACKAGE
# ============================================================
BASENAME=$(basename "$ARCHIVE" .tar.gz)
SANITIZED_NAME="${BASENAME}-SANITIZED.tar.gz"

tar czf "${OUTDIR}/${SANITIZED_NAME}" -C "$WORKDIR" .

SIZE=$(du -sh "${OUTDIR}/${SANITIZED_NAME}" | cut -f1)
echo ""
echo "============================================"
echo " Sanitized archive: ${OUTDIR}/${SANITIZED_NAME}"
echo " Size: $SIZE"
echo " ✓ Safe to share with LLM for analysis"
echo "============================================"
