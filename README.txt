PROXMOX UTILS — QUICK REFERENCE
================================
Repo: /opt/proxmox-utils-hetzner
Update: git pull

ALL SCRIPTS: dry-run by default. Add --apply to execute.

CONFIGS
-------
configs/upXXX.toml       Full server config (install, harden, network, template, VM)
configs/vms/*.toml        Lightweight VM-only configs (clone + publish)

CREATE VM FROM TEMPLATE
-----------------------
1. Copy and edit a VM config:
   cp configs/vms/example-vm.toml configs/vms/my-vm.toml
   vi configs/vms/my-vm.toml    # set vmid, name, ip, cores, memory, disk

2. Dry-run, then apply:
   bash scripts/vm-clone.sh configs/vms/my-vm.toml
   bash scripts/vm-clone.sh configs/vms/my-vm.toml --apply

ATTACH PUBLIC IP
----------------
1. In Hetzner Robot: order additional IP, request virtual MAC
2. Add [publish] section to your VM config:
   [publish]
   public_ip = "1.2.3.4"
   mac = "00:50:56:xx:xx:xx"

3. Run:
   bash scripts/vm-publish.sh configs/vms/my-vm.toml --apply

4. Reboot VM, then inside VM run:
   bash /tmp/vm-guest-publish.sh

DESTROY VM
----------
qm stop <VMID> && qm destroy <VMID> --purge

RESIZE DISK (live, no downtime)
-------------------------------
Host:   qm resize <VMID> scsi0 +100G
Guest:  growpart /dev/sda 2 && resize2fs /dev/sda2

REBUILD TEMPLATE
----------------
qm destroy 9000 --purge
bash scripts/vm-template.sh configs/upXXX.toml --apply

COMMON VM CONFIGS (configs/vms/*.toml)
--------------------------------------
Required sections: [nat], [template], [vm]
Optional section:  [publish]

Key [vm] fields:
  vmid          VM ID (101, 102, ...)
  name          Display name
  memory        RAM in MB (4096=4G, 65536=64G)
  cores         CPU cores
  disk_size     Disk size ("64G", "512G", "1T")
  ip            Static IP on NAT bridge ("10.10.10.11/24")
  cipassword    Console login password (empty = SSH-only)

Key [publish] fields:
  public_ip     Hetzner additional IP
  mac           Hetzner virtual MAC for that IP
  public_gw     Gateway (auto-detected if omitted)

SCRIPTS REFERENCE
-----------------
vm-template.sh      Create VM template (VMID 9000)
vm-clone.sh         Clone template → production VM
vm-publish.sh       Attach public IP to VM
vm-optimize.sh      Guest-side optimizations (baked into template)
pve-harden.sh       Host security hardening (14 steps)
pve-network.sh      NAT bridge setup (vmbr1)
pve-tunnel.sh       Cloudflare Tunnel for web UI
pve-tune.sh         Host performance tuning
pve-config-archive.sh   Backup all configs
pve-config-sanitize.sh  Strip secrets for sharing
vm-audit.sh         Health check / diagnostics
netbench.sh         Network benchmarks

SSH ACCESS (from Mac, via Cloudflare Tunnel)
--------------------------------------------
ssh fsn-ssh          → root@upfsn1 (Falkenstein)
ssh hel-ssh          → root@uphel1 (Helsinki)
ssh root@10.10.10.11 → VM (from inside Proxmox host)
