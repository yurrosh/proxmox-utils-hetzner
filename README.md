# proxmox-utils-hetzner

Automated Proxmox VE deployment and hardening toolkit for Hetzner dedicated servers.

Install, harden, and back up Proxmox VE — from bare metal to production in minutes.

## Quick Start

```bash
# From Hetzner Rescue System — install Proxmox:
bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-install-hetzner.sh)

# After reboot — harden:
bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-harden.sh) config.toml
```

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/pve-install-hetzner.sh` | Install Proxmox VE on Hetzner bare metal via QEMU |
| `scripts/pve-harden.sh` | Complete post-install security hardening |
| `scripts/pve-config-archive.sh` | Full configuration backup (includes secrets) |
| `scripts/pve-config-sanitize.sh` | Strip secrets from archive for safe external analysis |
| `scripts/netbench.sh` | Network latency/throughput benchmark to target regions |

## Configuration

All scripts share a single TOML config file per server. Two examples are included:

- `configs/example.toml` — generic template
- `configs/example-ax102.toml` — Hetzner AX102 (Ryzen 9 5950X, 128GB, NVMe)

```bash
cp configs/example-ax102.toml configs/myserver.toml
vi configs/myserver.toml   # set hostname, FQDN, SMTP key, email
```

Personal config files (`configs/*.toml` except examples) are gitignored — your secrets stay local.

## Installation

### One-liner (interactive)

Run from **Hetzner Rescue System** (Linux x64):

```bash
bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-install-hetzner.sh)
```

Prompts for hostname, FQDN, password, etc. Auto-detects network interface and disks.

### With config file

```bash
# Download and customize config
curl -sSLO https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/configs/example-ax102.toml
mv example-ax102.toml myserver.toml
vi myserver.toml

# Install (prompts only for root password if left empty in config)
bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-install-hetzner.sh) \
  --config myserver.toml
```

### Remote config

```bash
bash <(curl -sSL .../pve-install-hetzner.sh) \
  --config-url https://your-private-host.com/configs/myserver.toml
```

### Dry run

Preview everything without touching disks:

```bash
bash pve-install-hetzner.sh --config myserver.toml --dry-run
```

### What the installer does

1. **Pre-flight checks** — verifies disks exist, KVM available, interface up, UEFI/BIOS mode
2. Downloads latest Proxmox VE ISO
3. Generates `answer.toml` for the Proxmox auto-installer
4. Builds an autoinstall ISO (`proxmox-auto-install-assistant`)
5. Installs via QEMU to ZFS RAID-1 (disks passed as virtio drives)
6. Boots the installed system in QEMU, configures via SSH: hostname, network, DNS, sysctl
7. Verifies UEFI boot entries and ensures fallback bootloader exists
8. Disables enterprise repos, enables `pve-no-subscription`
9. Reboots into Proxmox on bare metal

### How disk mapping works

The TOML config `disk_list` contains **physical disk paths** as seen in the Hetzner rescue system (e.g. `/dev/nvme0n1`, `/dev/nvme1n1`). These are used as QEMU `-drive` arguments on the host side.

Inside QEMU, these disks appear as **virtio devices** (`/dev/vda`, `/dev/vdb`). The Proxmox auto-installer's `answer.toml` intentionally **omits** `disk-list` — since the QEMU VM only has the two drives we passed in, the installer auto-discovers them. This avoids any NVMe-to-virtio naming mismatch.

### UEFI boot handling

Most Hetzner dedicated servers (AX-series, EX-series) boot in UEFI mode. The installer:

- Detects UEFI via `/sys/firmware/efi`
- Uses **split OVMF firmware** (`OVMF_CODE.fd` + writable `OVMF_VARS.fd` copy) so EFI boot entries persist between the install and configure QEMU steps
- After installation, verifies the EFI System Partition (ESP) and boot entries
- Ensures the **EFI fallback bootloader** (`\EFI\BOOT\BOOTX64.EFI`) exists for bare-metal boot

> **Note**: Hetzner servers need UEFI rescue mode enabled for the physical reboot to work. If the server doesn't boot after installation, request UEFI rescue activation via Hetzner Robot or support — see [Hetzner UEFI docs](https://docs.hetzner.com/robot/dedicated-server/operating-systems/uefi/).

## Hardening

After install and reboot:

```bash
bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-harden.sh) myserver.toml
```

The hardening script applies 13 steps in one run:

1. **System update** — `apt update && upgrade`, `pveupgrade`
2. **Essential packages** — fail2ban, smartmontools, libguestfs-tools, at, etc.
3. **SSH** — `PermitRootLogin prohibit-password`
4. **APT repos** — disable enterprise, enable `pve-no-subscription`
5. **ZFS** — ARC min/max limits, monthly scrub, pool feature upgrade, initramfs rebuild
6. **SMART** — temperature monitoring (50°C warn / 70°C crit), scheduled self-tests
7. **Postfix** — SMTP relay via Brevo (SASL + TLS)
8. **Fail2ban** — SSH + Proxmox WebUI jails (3 retries / 10min / 1hr ban)
9. **Firewall** — DROP all, allow SSH + WebUI + ICMP (10-min safety rollback)
10. **Unattended upgrades** — Debian-Security + Proxmox, no auto-reboot
11. **Subscription nag** — removed
12. **Sysctl** — conntrack_max=1M, tcp_timeout=8h, nf_conntrack module preload
13. **rpcbind** — disabled and masked

## Config Backup & Audit

```bash
# Archive full config (contains secrets — store securely)
bash scripts/pve-config-archive.sh /root

# Sanitize for external review (strips keys, certs, password hashes)
bash scripts/pve-config-sanitize.sh /root/pve-config-*.tar.gz /root

# The SANITIZED archive is safe to share with LLM for config analysis
```

## Network Benchmark

Test latency and download speed to key regions:

```bash
bash scripts/netbench.sh myserver
# Outputs CSV: netbench_results_myserver_<date>.csv
```

## Repo Structure

```
proxmox-utils-hetzner/
├── scripts/
│   ├── pve-install-hetzner.sh    # Installer (curl-friendly)
│   ├── pve-harden.sh             # Security hardening (13 steps)
│   ├── pve-config-archive.sh     # Config backup
│   ├── pve-config-sanitize.sh    # Sanitize for external analysis
│   └── netbench.sh               # Network benchmarks
├── configs/
│   ├── example.toml              # Generic template
│   └── example-ax102.toml        # Hetzner AX102 template
├── .gitignore
├── LICENSE
└── README.md
```

## Hardware Tested

- **Hetzner AX102**: AMD Ryzen 9 5950X, 128GB ECC, 2× 3.84TB NVMe (Samsung PM9A3)
- **Proxmox VE 9.x** (Debian Trixie, kernel 6.17)
- **ZFS RAID-1** on NVMe

## Credits

Installer based on [ariadata/proxmox-hetzner](https://github.com/ariadata/proxmox-hetzner) (MIT License).

## License

MIT
