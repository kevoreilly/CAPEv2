# CAPEv2 — Ansible Deployment

Automated deployment of [CAPEv2](https://github.com/kevoreilly/CAPEv2) malware sandbox using Ansible.
Covers host installation (hypervisor, dependencies, CAPE core, signatures, system services, optional web stack)
and generates Windows guest VM provisioning scripts.

## Architecture

```
Epic 1 (Scaffolding)
  └── Epic 3 (Base OS + Tuning)
       ├── Epic 2 (Hypervisor) ─── auto-reboot ───┐
       ├── Epic 4 (CAPE core) ◄───────────────────┤
       │    ├── Epic 5 (Database)                 │
       │    └── Epic 6 (Signatures)               │
       └── Epic 7 (Systemd) ◄─────────────────────┘
            ├── Epic 8 (Optionals, via tags)
            ├── Epic 9 (Guest scripts, no live run)
            └── Epic 10 (Validation)
                 └── Epic 11 (Multi-node)
```

## Quick Start

```bash
cd ansible/

# 1. Set vault password
echo -n 'your-vault-password' > .vault_pass

# 2. Verify inventory resolves
ansible-inventory --list

# 3. Syntax check + dry-run (no changes made)
./ansible-deploy.sh --check

# 4. Full deployment (with confirmation prompt)
./ansible-deploy.sh

# 5. Post-deploy verification
ansible-playbook playbooks/verify.yml -i inventory/hosts.ini
```

## Directory Layout

```
ansible/
├── ansible.cfg               # Ansible configuration (vault, SSH pipelining, caching)
├── ansible-deploy.sh          # Deploy wrapper: syntax → dry-run → confirm → execute
├── .vault_pass                # Vault password file (gitignored, never commit)
├── site.yml                   # Master playbook — dispatches single or multi-node
├── plan.md                    # Build plan (11 Epics, reference for developers)
├── README.md                  # This file
│
├── inventory/
│   ├── hosts.ini              # Host groups
│   └── group_vars/
│       ├── all/
│       │   ├── vars.yml       # Global non-secret variables
│       │   └── vault.yml      # Encrypted secrets (vault)
│       ├── cape_host.yml      # Host-specific variables + anti-VM patterns
│       ├── cape_guests.yml    # Guest VM configuration
│       ├── cape_web.yml       # Multi-node web node overrides
│       └── cape_worker.yml    # Multi-node worker node overrides
│
├── playbooks/
│   ├── single-node.yml        # Full stack on one host
│   ├── multi-node-control.yml # Control node (hypervisor + all cape_host)
│   ├── multi-node-web.yml     # Web node (web UI, MongoDB, nginx only)
│   ├── multi-node-worker.yml  # Worker node (processing, signatures)
│   ├── register-worker.yml    # Register worker with control node
│   ├── deploy-sysmon.yml      # Deploy Sysmon to Windows guests via WinRM
│   ├── verify.yml             # Post-deployment health checks
│   ├── rollback.yml           # Full uninstall (reverses all changes)
│   └── smoke-test.yml         # Integration test: submit file + poll
│
├── roles/
│   ├── common/                # Base OS: APT deps, cape user, sysctl, Tor, de4dot
│   ├── hypervisor/            # QEMU + SeaBIOS + libvirt from source, virbr1, IOMMU
│   ├── cape_host/             # CAPE core: repo, config, DB, signatures, systemd, optional
│   └── guest_provisioning/    # Generates Windows guest scripts (.ps1/.bat) + Sysmon deploy
│       ├── tasks/sysmon.yml   # WinRM-based Sysmon deployment
│       └── templates/
│           └── sysmonconfig-capev2.xml.j2  # CAPEv2-tuned Sysmon config
│
├── generated_guest_scripts/   # Output directory for guest VM scripts
│
└── tests/
    ├── verify-scaffolding.yml # Structural integrity tests
    ├── test-common-role.yml
    ├── test-cape-host-role.yml
    ├── test-guest-provisioning.yml
    └── test-sysmon.yml
```

## Prerequisites

| Requirement | Version / Notes |
|-------------|----------------|
| Python      | 3.12+ |
| Ansible     | 10+ (`pip install ansible`) |
| Target OS   | Ubuntu 24.04 (Noble) |
| SSH access  | Root or passwordless sudo |
| Vault pass  | Create `.vault_pass` before first run |

```bash
pip install ansible
```

## Inventory Guide

### Host Groups (`inventory/hosts.ini`)

| Group | Purpose | Used In |
|-------|---------|---------|
| `cape_control` | Central node: database, hypervisor, scheduler, web UI | `single-node.yml`, `multi-node-control.yml` |
| `cape_web` | Alias for `cape_control` in single-node; separate host in multi-node | `multi-node-web.yml` |
| `cape_worker` | Analysis VMs, processing engines, signatures | `multi-node-worker.yml` |
| `cape_host` | Union of `cape_control` + `cape_worker` | `single-node.yml` |
| `cape_guests` | Metadata references for Windows VMs (not SSH targets) | `guest_provisioning` role |

### Single-Node Example

```ini
[cape_control]
cape-master ansible_host=10.0.0.10

[cape_host:children]
cape_control
```

Set `deployment_mode: single` in `group_vars/all/vars.yml` (default).

### Multi-Node Example

```ini
[cape_control]
cape-master ansible_host=10.0.0.10

[cape_worker]
worker-1 ansible_host=10.0.0.20
worker-2 ansible_host=10.0.0.21

[cape_host:children]
cape_control
cape_worker
```

Set `deployment_mode: multi` in `group_vars/all/vars.yml`.

### Guest VMs

```ini
[cape_guests]
win10-1 libvirt_name=win10_1 guest_ip=192.168.1.101
win10-2 libvirt_name=win10_2 guest_ip=192.168.1.102
```

These are metadata-only entries used for script generation. Guests are not managed via SSH.

### Guest VMs — WinRM (Remote Management)

```ini
[cape_guests_winrm]
win10-1 ansible_host=192.168.1.101 ansible_user=cape ansible_password=cape
         ansible_connection=winrm ansible_winrm_transport=basic
         ansible_winrm_server_cert_validation=ignore
         sysmon_install=true
```

Populate this group after initial Windows VM setup for remote management (Sysmon deployment, etc.).
WinRM is enabled automatically by `Autounattend.xml` (specialize pass). Requires `pywinrm`
on the control node: `pip install pywinrm`.

## Variable Reference

### Global (`group_vars/all/vars.yml`)

| Variable | Default | Description |
|----------|---------|-------------|
| `deployment_mode` | `single` | Topology: `single` or `multi` |
| `cape_root` | `/opt/CAPEv2` | Installation directory |
| `cape_user` | `cape` | System user for CAPE services |
| `use_uv` | `false` | Use `uv` instead of `poetry` |
| `network_iface` | `virbr1` | Internal bridge interface name |
| `iface_ip` | `192.168.1.1` | Host IP on the internal bridge |
| `internet_iface` | `""` | WAN interface (auto-detected if empty) |
| `dns_primary` | `8.8.8.8` | Primary DNS for bridge |
| `dns_secondary` | `8.8.4.4` | Secondary DNS |
| `db_user` | `cape` | PostgreSQL user |
| `db_name` | `cape` | PostgreSQL database name |
| `db_host` | `localhost` | Database host |
| `db_port` | `5432` | Database port |
| `mongo_enable` | `true` | Enable MongoDB (required for web UI) |
| `libvirt_version` | `11.1.0` | libvirt source version |
| `qemu_version` | `9.2.2` | QEMU source version |
| `seabios_version` | `1.16.3` | SeaBIOS source version |
| `nginx_version` | `1.27.3` | nginx source version (optional) |
| `prometheus_version` | `2.20.1` | Prometheus version (optional) |
| `grafana_version` | `7.1.5` | Grafana version (optional) |
| `csnb_version` | `1.0.8` | Crowdsec nginx bouncer version |
| `librenms_enable` | `false` | Enable LibreNMS monitoring support |
| `clamav_enable` | `false` | Enable ClamAV (optional) |
| `tor_socket_timeout` | `60` | Tor socket timeout in seconds |
| `snmp_community` | `ChangeMePublicRO` | SNMP community string |
| `ansible_connection` | `winrm` | Default connection type for WinRM guests |
| `ansible_winrm_transport` | `basic` | WinRM transport method |
| `ansible_winrm_server_cert_validation` | `ignore` | Skip WinRM cert validation (dev only) |
| `ansible_port` | `5985` | WinRM HTTP port |

### Host (`group_vars/cape_host.yml`)

| Variable | Default | Description |
|----------|---------|-------------|
| `db_connection_string` | *(dynamic)* | PostgreSQL URI (uses `vault_db_password`) |
| `cpuid` | `Intel(R) Core(TM) i3-4130 CPU` | CPUID anti-VM replacement |
| `qemu_hd_replacement` | *(commented)* | Disk model replacement string |
| `qemu_dvd_replacement` | *(commented)* | DVD model replacement string |
| `ansible_ssh_private_key_file` | `~/.ssh/id_rsa` | SSH key for multi-node |

### Guest VMs (`group_vars/cape_guests.yml`)

| Variable | Default | Description |
|----------|---------|-------------|
| `guest_os_type` | `windows` | Guest OS family |
| `agent_version` | `0.22` | CAPE agent version |
| `vm_cpu` | `2` | vCPUs per guest |
| `vm_memory_mb` | `4096` | RAM per guest (MB) |
| `vm_disk_gb` | `64` | Disk size (GB) |
| `vm_os_variant` | `win10` | libvirt OS variant |
| `resultserver_ip` | `{{ iface_ip }}` | Result server IP for agent |
| `resultserver_port` | `8000` | Result server port |
| `disable_defender` | `true` | Disable Windows Defender in script |
| `disable_firewall` | `true` | Disable Windows Firewall |
| `python_installer_url` | *(see file)* | Python download URL for guest |
| `sysmon_install` | `false` | Deploy Sysmon via WinRM (set `true` per guest) |
| `sysmon_version` | `""` | Sysmon version to install (empty = latest) |
| `sysmon_config_source` | `template` | Config source: `template` (CAPEv2 default) or `file` |
| `sysmon_config_file` | `""` | Path to custom Sysmon XML config (when source: `file`) |
| `sysmon_install_dir` | `C:\Sysmon` | Sysmon installation directory on guest |

### Secrets (`group_vars/all/vault.yml` — encrypted with Ansible Vault)

| Variable | Description |
|----------|-------------|
| `vault_db_password` | PostgreSQL password |
| `vault_snmp_community` | SNMP community string |
| `vault_letsencrypt_email` | Let's Encrypt registration email |

### Role Defaults

**`roles/hypervisor/defaults/main.yml`** — QEMU, SeaBIOS, libvirt versions, build dirs,
source URLs, all anti-VM replacement strings (CPUID, disk, DVD, ACPI dates, etc.),
virbr1 network range and DHCP pool.

**`roles/common/defaults/main.yml`** — Tor ports (`control: 9051`, `dns: 5353`, `trans: 9040`),
de4dot version and download URL.

**`roles/cape_host/defaults/main.yml`** — CAPE repo URL, tcpdump path.

**`roles/guest_provisioning/defaults/main.yml`** — Script output directory, agent Python version,
VC++ redist year, Sysmon install defaults.

## Deploy Script (`ansible-deploy.sh`)

The wrapper runs three stages in sequence:

| Step | Command | Description |
|------|---------|-------------|
| 1 | `--syntax-check` | Validates playbook YAML and variable resolution |
| 2 | `--check --diff` | Dry-run showing intended changes |
| 3 | (user confirmation) | Executes the playbook for real |

### Flags

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
| `-h, --help` | Show help |

### Environment Overrides

| Variable | Overrides |
|----------|-----------|
| `ANSIBLE_PLAYBOOK` | Default playbook |
| `ANSIBLE_INVENTORY` | Default inventory path |
| `ANSIBLE_VAULT_PASS` | Vault password file path |

### Examples

```bash
# Full deploy with default playbook (site.yml)
./ansible-deploy.sh

# Specific playbook to a single host
./ansible-deploy.sh -p playbooks/single-node.yml -l cape-master

# Only optional components (nginx, guacamole, clamav, etc.)
./ansible-deploy.sh -t optional

# Skip all optional components
./ansible-deploy.sh --skip-tags optional

# Dry-run only — no changes made
./ansible-deploy.sh --check

# Pass extra variables
./ansible-deploy.sh -e "deployment_mode=multi use_uv=true"
```

## Playbook Reference

### `site.yml` — Master Dispatcher

Entry point. Inspects `deployment_mode` and dispatches to the appropriate playbook:

- `single` → `playbooks/single-node.yml`
- `multi`  → `playbooks/multi-node-{control,web,worker}.yml`

```bash
./ansible-deploy.sh                              # via wrapper
ansible-playbook site.yml -i inventory/hosts.ini  # directly
```

### `single-node.yml` — Full Stack Deployment

Runs every role: `common` → `hypervisor` → `cape_host` (all sub-tasks) → `guest_provisioning`.

```bash
ansible-playbook playbooks/single-node.yml -i inventory/hosts.ini
```

### Multi-Node Playbooks

| Playbook | Target Group | What It Deploys |
|----------|-------------|-----------------|
| `multi-node-control.yml` | `cape_control` | common, hypervisor, full cape_host, guest scripts, SSH key generation |
| `multi-node-web.yml` | `cape_web` | common, minimal repo/config, MongoDB, cape-web, nginx |
| `multi-node-worker.yml` | `cape_worker` | common, repo, config, signatures, remote DB/resultserver |
| `register-worker.yml` | `cape_worker` | Authorize SSH key, set remote connection strings, verify PG connectivity |

```bash
# Deploy all multi-node nodes
ansible-playbook playbooks/multi-node-control.yml -i inventory/hosts.ini
ansible-playbook playbooks/multi-node-web.yml -i inventory/hosts.ini
ansible-playbook playbooks/multi-node-worker.yml -i inventory/hosts.ini

# Register a worker after control node is deployed
ansible-playbook playbooks/register-worker.yml -i inventory/hosts.ini -l worker-1
```

### `verify.yml` — Post-Deployment Health Checks

Checks that everything is running correctly:

- Systemd services: `postgresql`, `tor`, `cape`, `cape-rooter`, `cape-processor`, `suricata`
- Optional services: `mongodb`, `nginx`, `guacd`, `guac-web`, `clamav-daemon`, `fail2ban`, `crowdsec`
- PostgreSQL accepts connections with vault credentials
- MongoDB responds (if enabled)
- YARA version is printed
- Suricata is configured on `{{ network_iface }}`
- Tor control and DNS ports are listening
- Result server port (`8000`) is listening
- Web UI returns content matching "CAPEv2" or "cape"

```bash
ansible-playbook playbooks/verify.yml -i inventory/hosts.ini
```

### `rollback.yml` — Full Uninstall

Reverses every change the playbooks make. Reverts:

- All systemd services (stop, disable, remove unit files)
- CAPE root directory, cape user, home directory
- PostgreSQL database, user, packages, APT repo
- MongoDB data directories, packages, APT repo
- Sudoers entries
- sysctl, limits, modules load config
- rt_tables internet entry, tcp_fastopen
- Tor configuration and package
- de4dot
- virbr1 network, libvirtd, libvirt, QEMU, SeaBIOS
- nginx, guacamole, fail2ban, ClamAV, crowdsec, Grafana, Prometheus
- Logrotate configs
- Crontab entries
- GRUB IOMMU kernel parameter
- Orphaned APT packages

```bash
ansible-playbook playbooks/rollback.yml -i inventory/hosts.ini
```

**Warning:** This destroys all data. A confirmation prompt is shown before changes are applied.

### `smoke-test.yml` — Integration Test

Creates a benign text file, submits it via the CAPE API (`/apiv2/tasks/create/file/`),
polls for completion (up to 5 minutes), and asserts the report contains expected fields.

```bash
ansible-playbook playbooks/smoke-test.yml -i inventory/hosts.ini
```

## Tag-Based Execution

Every role and sub-task is tagged, allowing fine-grained control over what runs.

| Tag | What It Runs |
|-----|-------------|
| `common` | All base OS tasks |
| `dependencies` | APT packages |
| `cape_user` | User and group creation |
| `python` | Poetry or uv installation |
| `sysctl` | Kernel parameters, limits, modules |
| `locale` | en_US.UTF-8, UTC timezone |
| `de4dot` | .NET deobfuscator |
| `tor` | Tor repository, installation, torrc |
| `hypervisor` | All hypervisor tasks |
| `kvm_qemu` | QEMU compile with anti-VM patches |
| `seabios` | SeaBIOS compile with anti-VM patches |
| `libvirt` | libvirt compile |
| `iommu` | GRUB `intel_iommu=on`, reboot |
| `network` | virbr1 bridge creation |
| `cape_host` | All CAPE core tasks |
| `repo` | Clone CAPEv2, venv, sync, yara-python |
| `config` | Config copy, PostgreSQL URI, community sigs, sudoers, rt_tables |
| `database` | PostgreSQL, MongoDB, Alembic migrations |
| `signatures` | YARA, Suricata, volatility3, CAPA, crontab |
| `systemd` | Unit files, enable services, logrotate, jemalloc |
| `optional` | All optional components (skippable with `--skip-tags optional`) |
| `nginx` | nginx compile + configure |
| `letsencrypt` | certbot certificate |
| `guacamole` | Guacamole compile + systemd |
| `clamav` | ClamAV + unofficial sigs |
| `fail2ban` | fail2ban install + jail.local |
| `prometheus` | Prometheus + Grafana |
| `modsecurity` | ModSecurity v3 + nginx module |
| `crowdsec` | Crowdsec + nginx bouncer |
| `guest` | All guest provisioning scripts |
| `harden` | harden.ps1 + harden.bat |
| `deps` | install_deps.ps1 |
| `agent` | deploy_agent.ps1 + uninstall_agent.ps1 |
| `config` | config.ini |
| `instructions` | SNAPSHOT_INSTRUCTIONS.md |
| `sysmon` | Sysmon deployment via WinRM |

### Examples

```bash
# Only run the database tasks
./ansible-deploy.sh -t database

# Run everything except signatures
./ansible-deploy.sh --skip-tags signatures

# Only nginx and guacamole
./ansible-deploy.sh -t nginx,guacamole

# Deploy the cape_host role without the repo clone
./ansible-deploy.sh -t cape_host --skip-tags repo
```

## Ansible Vault

Secrets are stored encrypted in `inventory/group_vars/all/vault.yml`.

### Setup

```bash
# Create vault password file (gitignored)
echo -n 'your-strong-password' > .vault_pass

# The vault is ready — `ansible.cfg` references `.vault_pass` automatically
```

### Common Operations

```bash
# Edit secrets (opens $EDITOR)
ansible-vault edit inventory/group_vars/all/vault.yml

# View decrypted content
ansible-vault view inventory/group_vars/all/vault.yml

# Rotate vault password
ansible-vault rekey inventory/group_vars/all/vault.yml

# Verify vault works
ansible-inventory --list --vault-password-file .vault_pass
```

**Never commit `.vault_pass`.** It is in `.gitignore`. If you lose it, you cannot recover the vault.

## Guest VM Provisioning

Guest provisioning is **manual by design**. The `guest_provisioning` role generates
`.ps1` and `.bat` scripts under `generated_guest_scripts/` that must be transferred
to the Windows guest VM and executed there. No WinRM connection is required.

### Generated Scripts

| File | Purpose |
|------|---------|
| `harden.ps1` | Disable Defender, Firewall, SmartScreen, telemetry, scheduled tasks |
| `harden.bat` | Same as above but Batch (for older guests) |
| `install_deps.ps1` | Install Python `{{ agent_python_version }}`, pip packages (pillow, pywintrace) |
| `deploy_agent.ps1` | Copy `agent.py`, register as Windows service `CAPEAgent`, test TCP connectivity |
| `uninstall_agent.ps1` | Stop service, remove files (rollback) |
| `config.ini` | Result server IP and port |
| `SNAPSHOT_INSTRUCTIONS.md` | Step-by-step guide from start to libvirt snapshot |

### Recommended Workflow

```
1. Transfer all files from generated_guest_scripts/ to the Windows guest
2. As Administrator: powershell Set-ExecutionPolicy Bypass -Scope Process -Force; .\harden.ps1
3. Reboot guest
4. As Administrator: .\install_deps.ps1
5. Copy agent.py into the same directory (from {{ cape_root }}/agent/agent.py)
6. As Administrator: .\deploy_agent.ps1
7. Shut down guest
8. On host: virsh snapshot-create-as <vm-name> --name clean --description "Ready"
9. Update conf/kvm.conf with the VM and snapshot name
```

## Sysmon Deployment (WinRM)

[Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) is deployed
to Windows guest VMs via WinRM for enhanced visibility into process creation, network
connections, DNS queries, and registry changes. The CAPEv2-tuned configuration captures
exactly the events that `network_etw.py` and `evtx.py` process for behavioral analysis.

### Prerequisites

```bash
pip install pywinrm
```

### Setup

1. Add guest VMs to `[cape_guests_winrm]` in `inventory/hosts.ini`
2. Set `sysmon_install=true` on each guest you want to deploy to
3. Ensure WinRM is accessible (enabled by default via `Autounattend.xml`)

### Deploy

```bash
# Deploy to all guests in [cape_guests_winrm] with sysmon_install=true
ansible-playbook playbooks/deploy-sysmon.yml -i inventory/hosts.ini

# Deploy to a specific guest
ansible-playbook playbooks/deploy-sysmon.yml -i inventory/hosts.ini --limit win10-1

# Pin a specific Sysmon version
ansible-playbook playbooks/deploy-sysmon.yml -i inventory/hosts.ini -e "sysmon_version=15.12"

# Dry-run
ansible-playbook playbooks/deploy-sysmon.yml -i inventory/hosts.ini --check --diff
```

### Custom Sysmon Configuration

To use your own Sysmon XML config instead of the built-in CAPEv2 template:

```ini
# In inventory/hosts.ini or group_vars
sysmon_config_source: file
sysmon_config_file: /path/to/your/sysmonconfig.xml
```

### Verification

On the guest VM (via RDP or console):

```powershell
Get-Service Sysmon                          # Should show Running
sysmon -c                                  # Shows active configuration
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
```

### Rollback

```powershell
# On the guest VM
C:\Sysmon\Sysmon64.exe -u                   # Stop and remove Sysmon service
Remove-Item -Recurse C:\Sysmon              # Remove installation directory
```

## Development & Testing

### Syntax Check All Playbooks

```bash
# Run the scaffolding integrity tests
ansible-playbook tests/verify-scaffolding.yml -i localhost, --connection=local

# Syntax check individual role test playbooks
ansible-playbook --syntax-check tests/test-common-role.yml -i localhost, --connection=local
ansible-playbook --syntax-check tests/test-cape-host-role.yml -i localhost, --connection=local \
  --extra-vars "vault_db_password=test internet_iface=eth0"
ansible-playbook --syntax-check tests/test-guest-provisioning.yml -i localhost, --connection=local

# Full dry-run against localhost (no changes made)
./ansible-deploy.sh --check

# Validate YAML of all task files
for f in $(find roles -name '*.yml'); do python3 -c "import yaml; yaml.safe_load(open('$f'))" && echo "$f OK"; done
```

### Workflow for Adding New Tasks

1. Add a task file under `roles/<role>/tasks/<feature>.yml`
2. Include it in `roles/<role>/tasks/main.yml` with appropriate tags
3. Add defaults in `roles/<role>/defaults/main.yml` if needed
4. Run `ansible-playbook --syntax-check tests/test-<role>.yml`
5. Run `./ansible-deploy.sh --check` for a full dry-run
6. Commit with a descriptive message following conventional commits

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| `vault_password_file` error | Missing `.vault_pass` | `echo -n 'password' > .vault_pass` |
| `ansible-vault` prompts for password | `ansible.cfg` not found | Run from `ansible/` directory |
| Host unreachable | SSH key not deployed | `ssh-copy-id root@<host>` |
| Check mode skips tasks | `command`/`shell` modules used | Normal — those modules cannot report changes in check mode |
| `ansible-inventory` shows no vault vars | Vault file structure wrong | Ensure vars are in `all/vault.yml` inside `all/` directory |
| POSTGRESQL: `role "cape" does not exist` | Vault password wrong or DB user not created | Check `vault_db_password`, re-run database tasks |
| MONGODB: `AVX not supported` | CPU lacks AVX, fallback to MongoDB 4.4 | Automatic fallback; no action needed |
| QEMU compile fails | Missing build dependencies | `apt install build-essential` — check `installer/kvm-qemu.sh` for full list |
| `intel_iommu=on` not in GRUB after reboot | Reboot interrupted | Re-run hypervisor role or manually `update-grub` |
| Nginx won't start | Port 80/443 in use | `netstat -tlnp \| grep -E ':(80|443)'` and free the port |
| Agent connectivity fails | Firewall on host blocks port | `iptables -A INPUT -p tcp --dport 8000 -s 192.168.1.0/24 -j ACCEPT` |
| Suricata fails to start | Interface wrong | Check `network_iface` var and `/etc/suricata/suricata.yaml` |
| `make` runs out of memory | Insufficient RAM for compile | Add swap or reduce `-j` threads: `make -j1` |

## Commit History

```
366c1301 feat: add multi-node orchestration and master site playbook
b1c2a133 feat: add verification, rollback, and smoke test playbooks
7a39eef5 feat: add guest provisioning role with hardening, deps, agent, and instructions
639caa47 feat: add optional components role (nginx, guacamole, clamav, fail2ban, prometheus, modsecurity, crowdsec)
5e9a8db0 feat: add systemd services role with unit files, enable, logrotate, jemalloc
c67dd420 feat: add signatures and detection engines role
c3cc2eda feat: add database layer role with PostgreSQL, MongoDB, and Alembic migrations
7cdd66dc feat: add cape_host role with repo clone, venv, yara-python, and config
0a257f55 feat: add common role with base OS dependencies and system tuning
d0c5ae35 feat: add libvirt build, config, network, and IOMMU roles
3c671b4b feat: add SeaBIOS compile role with anti-VM replacements
e77a1d66 feat: add hypervisor/kvm_qemu role for compiling QEMU from source
94a6abb2 feat: add ansible/README.md with usage, variables, vault, and troubleshooting docs
958f6a3a feat: create ansible-deploy.sh wrapper with syntax-check, dry-run, confirmation, and execute
6508231e feat: migrate group_vars/all to directory format for vault compatibility
de85895d feat(ansible): add group_vars for hosts, guests, and multi-node modes
d96136b9 feat(ansible): add inventory with single-node and multi-node groups
229bab73 feat(ansible): add project scaffolding and inventory layout
```
