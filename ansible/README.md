# CAPEv2 — Ansible Deployment

Automated deployment of [CAPEv2](https://github.com/kevoreilly/CAPEv2) malware sandbox using Ansible.

Covers host installation (hypervisor, dependencies, CAPE core, signatures) and guest VM provisioning script generation.

## Directory Layout

```
ansible/
├── ansible.cfg                         # Project Ansible configuration
├── ansible-deploy.sh                   # Deploy wrapper: syntax → dry-run → confirm → execute
├── site.yml                            # Entry playbook (default: host-deploy.yml)
├── playbooks/
│   ├── host-deploy.yml                 # CAPE host installation
│   ├── guest-provision.yml             # Generate guest provisioning scripts
│   ├── multi-node-web.yml              # Web/control node (multi-node)
│   ├── multi-node-worker.yml           # Worker node (multi-node)
│   └── register-worker.yml             # Register worker with control node
├── inventory/
│   ├── hosts.ini                       # Host groups
│   ├── group_vars/all/vars.yml         # Global non-secret vars
│   ├── group_vars/all/vault.yml        # Encrypted secrets (vault)
│   ├── group_vars/cape_host.yml        # Host-specific vars
│   ├── group_vars/cape_guests.yml      # Guest VM vars
│   ├── group_vars/cape_worker.yml      # Multi-node worker overrides
│   └── group_vars/cape_web.yml         # Multi-node web/control overrides
│   └── host_vars/                      # Per-host overrides
├── roles/
│   ├── common/                         # Base OS tuning (apt, sysctl, limits, tor, cape user)
│   ├── hypervisor/                     # KVM + QEMU + Libvirt from source
│   ├── cape_host/                      # CAPE core (deps, repo, db, signatures, config, systemd)
│   └── cape_guest/                     # Guest provisioning script templates
├── generated_guest_scripts/            # Output: generated .ps1/.bat for Windows VMs
└── tests/                              # Scaffolding and smoke test playbooks
```

## Prerequisites

- Python 3.12+ with `pip`
- Ansible 10+ (`pip install ansible`)
- Target host(s) running Ubuntu 24.04 with SSH access as root
- (Optional) `ansible-vault` for secrets management

## Quick Start

```bash
# 1. Set up the vault password
echo -n 'your-vault-password' > .vault_pass

# 2. Verify inventory
ansible-inventory --list

# 3. Syntax check + dry-run (no changes)
./ansible-deploy.sh --check

# 4. Full deployment (with confirmation prompt)
./ansible-deploy.sh
```

## Deploy Script

`ansible-deploy.sh` runs three stages in sequence:

| Step | Command | Description |
|------|---------|-------------|
| 1 | `--syntax-check` | Validates playbook YAML and variable resolution |
| 2 | `--check --diff` | Dry-run showing intended changes |
| 3 | (confirmation) | Executes the playbook for real |

### Options

| Flag | Description |
|------|-------------|
| `-p, --playbook FILE` | Playbook to run (default: `site.yml`) |
| `-i, --inventory FILE` | Inventory file (default: `inventory/hosts.ini`) |
| `-v, --vault-pass FILE` | Vault password file (default: `.vault_pass`) |
| `-l, --limit HOSTS` | Limit to specific hosts/groups |
| `-t, --tags TAGS` | Only run tasks with these tags |
| `--skip-tags TAGS` | Skip tasks with these tags |
| `--check` | Only syntax + dry-run, skip execution |
| `--diff` | Show full diff output |
| `-e, --extra-var K=V` | Pass extra variables (repeatable) |

### Examples

```bash
# Full deploy with default playbook
./ansible-deploy.sh

# Deploy specific playbook to specific host
./ansible-deploy.sh -p playbooks/host-deploy.yml -l cape-host01

# Only optional components (nginx, guacamole, clamav, etc.)
./ansible-deploy.sh -t optional

# Skip optional components
./ansible-deploy.sh --skip-tags optional

# Dry-run only, no execution
./ansible-deploy.sh --check --diff
```

## Variable Reference

### Global (`group_vars/all/vars.yml`)

| Variable | Default | Description |
|----------|---------|-------------|
| `deployment_mode` | `single` | Topology: `single` or `multi` |
| `cape_root` | `/opt/CAPEv2` | Installation directory |
| `cape_user` | `cape` | System user for services |
| `use_uv` | `false` | Use `uv` instead of `poetry` |
| `network_iface` | `virbr1` | Internal bridge interface |
| `iface_ip` | `192.168.1.1` | Host IP on the bridge |
| `internet_iface` | `""` | WAN interface (auto if empty) |
| `dns_primary` | `8.8.8.8` | DNS for bridge |
| `dns_secondary` | `8.8.4.4` | Secondary DNS |
| `db_user` | `cape` | PostgreSQL user |
| `db_name` | `cape` | PostgreSQL database |
| `db_host` | `localhost` | Database host |
| `db_port` | `5432` | Database port |
| `mongo_enable` | `true` | Enable MongoDB |
| `libvirt_version` | `11.1.0` | libvirt source version |
| `qemu_version` | `9.2.2` | QEMU source version |
| `seabios_version` | `1.16.3` | SeaBIOS source version |

### Host (`group_vars/cape_host.yml`)

| Variable | Default | Description |
|----------|---------|-------------|
| `db_connection_string` | *(dynamic)* | PostgreSQL URI using `vault_db_password` |
| `ansible_ssh_private_key_file` | `~/.ssh/id_rsa` | SSH key for multi-node |
| `cpuid` | `Intel(R) Core(TM) i3-4130 CPU` | CPUID anti-VM replacement |
| `qemu_hd_replacement` | *(commented)* | Disk model replacement string |
| `qemu_dvd_replacement` | *(commented)* | DVD model replacement string |

### Guest VMs (`group_vars/cape_guests.yml`)

| Variable | Default | Description |
|----------|---------|-------------|
| `guest_os_type` | `windows` | Guest OS family |
| `agent_version` | `0.22` | CAPE agent version |
| `agent_install_path` | `C:\CAPE\agent` | Agent install directory |
| `vm_cpu` | `2` | vCPUs per guest |
| `vm_memory_mb` | `4096` | RAM in MB |
| `vm_disk_gb` | `64` | Disk size in GB |
| `vm_os_variant` | `win10` | libvirt OS variant |
| `resultserver_ip` | `{{ iface_ip }}` | Host result server IP |
| `resultserver_port` | `8000` | Result server port |
| `disable_defender` | `true` | Disable Windows Defender |
| `python_installer_url` | *(see file)* | Python download URL |

### Secrets (`group_vars/all/vault.yml` — encrypted)

| Variable | Description |
|----------|-------------|
| `vault_db_password` | PostgreSQL password |
| `vault_snmp_community` | SNMP community string |
| `vault_letsencrypt_email` | Let's Encrypt registration email |

### Multi-Node Overrides

**Worker** (`group_vars/cape_worker.yml`): Sets `db_host` to control node IP, disables web UI, enables libvirt.

**Web/Control** (`group_vars/cape_web.yml`): Enables PostgreSQL, MongoDB, web UI, scheduler; disables processing and VMs.

## Ansible Vault

Secrets are stored encrypted in `group_vars/all/vault.yml`.

```bash
# Edit secrets
ansible-vault edit inventory/group_vars/all/vault.yml

# View plaintext
ansible-vault view inventory/group_vars/all/vault.yml

# Re-key (change password)
ansible-vault rekey inventory/group_vars/all/vault.yml
```

The vault password file is `.vault_pass` (gitignored, never commit). `ansible.cfg` references it automatically.

## Tag-Based Execution

Components are gated by tags:

| Tag | Components |
|-----|------------|
| *(no tag)* | Core installation (always runs) |
| `optional` | nginx, guacamole, clamav, fail2ban, prometheus, modsecurity, crowdsecurity |

Use `--tags` or `--skip-tags` with the deploy script:

```bash
# Skip all optional components
./ansible-deploy.sh --skip-tags optional

# Only optional components
./ansible-deploy.sh -t optional

# Only nginx
./ansible-deploy.sh -t nginx
```

## Topology

### Single-Node (default)

All services run on one host. Set `deployment_mode: single` in `group_vars/all/vars.yml` and add the host to `[cape_host]`.

### Multi-Node

Set `deployment_mode: multi` and assign hosts to:
- `[cape_web]` — web interface, database, scheduler
- `[cape_worker]` — processing engines, VMs

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| `vault_password_file` error | Missing `.vault_pass` | `echo -n 'password' > .vault_pass` |
| `ansible-vault` prompts for password | `ansible.cfg` not found | Run from `ansible/` directory |
| Host unreachable | SSH key not deployed | Use `ssh-copy-id` or set `ansible_user`/`ansible_password` |
| Check mode skips tasks | `command`/`shell` modules | Normal behavior; actual run will apply those |
| `ansible-inventory` shows no vault vars | `group_vars/all/` directory format | Ensure vars are in `vars.yml` inside `all/` directory |

## Verification

Run the scaffolding verification playbook at any time:

```bash
ansible-playbook tests/verify-scaffolding.yml -i localhost, --connection=local
```
