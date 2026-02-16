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

### Host setup (run on Proxmox host)

| Script | Purpose |
|--------|---------|
| `pve-install-hetzner.sh` | Install Proxmox VE on Hetzner bare metal via QEMU |
| `pve-harden.sh` | Complete post-install security hardening (14 steps) |
| `pve-network.sh` | NAT bridge for VM outbound internet |
| `pve-tunnel.sh` | Cloudflare Tunnel for web UI + SSH access (no VPN needed) |
| `pve-config-archive.sh` | Full configuration backup (includes secrets) |
| `pve-config-sanitize.sh` | Strip secrets from archive for safe external analysis |

### VM management (run on Proxmox host)

| Script | Purpose |
|--------|---------|
| `vm-template.sh` | Create VM template from Debian/Ubuntu cloud image + Docker |
| `vm-clone.sh` | Clone template to production VM with specified resources |
| `vm-publish.sh` | Attach Hetzner public IP to VM (supports ifupdown + netplan) |

### VM tools (run inside VM)

| Script | Purpose |
|--------|---------|
| `vm-optimize.sh` | Production tuning: sysctl, zram, BBR, Docker, limits |
| `vm-audit.sh` | Comprehensive system audit + optional benchmarks |

### Utilities

| Script | Purpose |
|--------|---------|
| `netbench.sh` | Network latency/throughput benchmark to target regions |

## Workflow

```
1. Rescue boot  →  pve-install-hetzner.sh  →  Proxmox installed
2. First boot   →  pve-harden.sh           →  SSH, firewall, ZFS, fail2ban, SMTP
3. Networking   →  pve-network.sh          →  NAT bridge for VMs
4. Access       →  pve-tunnel.sh           →  Cloudflare Tunnel (close port 8006)
5. Template     →  vm-template.sh          →  Debian 13 + Docker template
6. Clone        →  vm-clone.sh             →  Production VM (64GB, 16 cores)
7. Public IP    →  vm-publish.sh           →  Hetzner additional IP attached
8. Deploy       →  docker compose up       →  Containers running
```

## Configuration

All scripts share a single TOML config file per server:

```bash
cp configs/example.toml configs/myserver.toml
vi configs/myserver.toml   # set hostname, FQDN, SMTP key, email
```

Personal config files (`configs/*.toml` except examples) are gitignored.

### Config sections

| Section | Used by | Purpose |
|---------|---------|---------|
| `[server]` | `pve-install-hetzner.sh` | Hostname, FQDN, timezone |
| `[network]` | `pve-install-hetzner.sh` | Interface, DNS |
| `[disk]` | `pve-install-hetzner.sh` | ZFS RAID, disk list |
| `[users]` | `pve-install-hetzner.sh` | Root password, email |
| `[hardening]` | `pve-harden.sh` | SSH, firewall, ZFS ARC, SMTP, fail2ban |
| `[nat]` | `pve-network.sh` | NAT bridge (vmbr1) |
| `[template]` | `vm-template.sh` | Cloud image, VMID, resources |
| `[vm]` | `vm-clone.sh` | Production VM resources |

## Installation

### One-liner (interactive)

Run from **Hetzner Rescue System** (Linux x64):

```bash
bash <(curl -sSL https://github.com/yurrosh/proxmox-utils-hetzner/raw/main/scripts/pve-install-hetzner.sh)
```

### With config file

```bash
bash <(curl -sSL .../pve-install-hetzner.sh) --config myserver.toml
```

### Dry run

```bash
bash pve-install-hetzner.sh --config myserver.toml --dry-run
```

### What the installer does

1. Detects hardware (disks, interface, UEFI/BIOS)
2. Downloads latest Proxmox VE ISO
3. Generates `answer.toml` for the Proxmox auto-installer
4. Installs via QEMU to ZFS RAID-1
5. Configures hostname, network, DNS, sysctl via SSH
6. Ensures UEFI fallback bootloader exists
7. Reboots into Proxmox on bare metal

## Hardening

After install and reboot:

```bash
bash <(curl -sSL .../pve-harden.sh) myserver.toml
```

14 steps in one run:

1. System update (apt + pveam)
2. Essential packages (fail2ban, smartmontools, libguestfs-tools, etc.)
3. SSH hardening (key-only auth)
4. APT repos (disable enterprise, enable community)
5. ZFS tuning (ARC limits, monthly scrub, initramfs)
6. SMART monitoring (temperature alerts, scheduled tests)
7. Postfix SMTP relay (Brevo/Sendinblue)
8. Fail2ban (SSH + Proxmox WebUI jails)
9. Firewall (DROP all, allow SSH + ICMP, 10-min safety rollback)
10. Unattended upgrades (Debian-Security + Proxmox)
11. Subscription nag removal
12. Sysctl (conntrack tuning)
13. Disable rpcbind
14. Disable KSM (saves CPU on non-overprovisioned hosts)

## Cloudflare Tunnel

Secure access to Proxmox web UI and SSH without exposing ports:

```bash
# Create tunnel in Cloudflare Zero Trust dashboard first, then:
bash scripts/pve-tunnel.sh <TUNNEL_TOKEN>

# Close port 8006 from firewall (tunnel handles access):
sed -i '/dport 8006/d' /etc/pve/firewall/cluster.fw && pve-firewall restart
```

After setup, access Proxmox at `https://pve-xxx.yourdomain.com` with email OTP authentication.

## VM Template + Clone

```bash
# Create template (Debian 13 + Docker + optimizations baked in):
bash scripts/vm-template.sh myserver.toml --apply

# Clone to production VM:
bash scripts/vm-clone.sh myserver.toml --apply

# Attach public IP:
bash scripts/vm-publish.sh 101 142.132.197.241 00:50:56:00:6A:A4 --apply
```

## Config Backup & Audit

```bash
# Archive full config (contains secrets — store securely)
bash scripts/pve-config-archive.sh /root

# Sanitize for external review (safe to share with LLM)
bash scripts/pve-config-sanitize.sh /root/pve-config-*.tar.gz /root

# Audit VM (run inside VM)
bash scripts/vm-audit.sh          # config check
bash scripts/vm-audit.sh --bench  # + benchmarks
```

## Repo Structure

```
proxmox-utils-hetzner/
├── scripts/
│   ├── pve-install-hetzner.sh    # Installer (curl-friendly)
│   ├── pve-harden.sh             # Security hardening (14 steps)
│   ├── pve-network.sh            # NAT bridge setup
│   ├── pve-tunnel.sh             # Cloudflare Tunnel setup
│   ├── pve-config-archive.sh     # Config backup
│   ├── pve-config-sanitize.sh    # Sanitize for external analysis
│   ├── vm-template.sh            # Create VM template from cloud image
│   ├── vm-clone.sh               # Clone template to production VM
│   ├── vm-publish.sh             # Attach public IP to VM
│   ├── vm-optimize.sh            # Production VM tuning
│   ├── vm-audit.sh               # System audit + benchmarks
│   └── netbench.sh               # Network benchmarks
├── configs/
│   └── example.toml              # Config template
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
