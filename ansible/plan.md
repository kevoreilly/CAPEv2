# CAPEv2 Ansible Deployment Plan

## Project Layout

```
ansible/
├── ansible.cfg
├── site.yml                     # Entry: runs both playbooks (single or multi-node)
├── ansible-deploy.sh            # Wrapper (syntax-check → dry-run → confirmation → execute)
├── verify.yml                   # Post-deployment smoke tests
├── rollback.yml                 # Reverse all changes
├── inventory/
│   ├── hosts.ini                # [cape_control], [cape_web], [cape_worker], [cape_host], [cape_guests]
│   ├── group_vars/
│   │   ├── all.yml              # deployment_mode: single|multi
│   │   ├── cape_host.yml        # cape_root, iface, db_password (vault)
│   │   ├── cape_worker.yml      # (multi-node) worker-specific overrides
│   │   ├── cape_web.yml         # (multi-node) web-specific overrides
│   │   └── cape_guests.yml      # agent_path, vm_memory, etc.
│   └── host_vars/
│       └── guest-win10.yml      # Per-guest overrides
├── generated_guest_scripts/     # Scripts for manual execution on Windows VMs
│   ├── README.md
│   ├── harden.ps1
│   ├── harden.bat
│   ├── install_deps.ps1
│   ├── deploy_agent.ps1
│   ├── uninstall_agent.ps1
│   ├── config.ini
│   └── SNAPSHOT_INSTRUCTIONS.md
├── playbooks/
│   ├── host-deploy.yml          # Step 1 — CAPE host installation
│   ├── guest-provision.yml      # Step 2 — Guest script generation (no live run)
│   ├── multi-node-web.yml       # Web node (multi-node mode)
│   ├── multi-node-worker.yml    # Worker node (multi-node mode)
│   └── register-worker.yml      # Register worker with control node
└── roles/
    ├── common/                  # Base OS tuning (apt, sysctl, limits, locale, tor, poetry/uv, cape user)
    ├── hypervisor/              # KVM + QEMU + Libvirt from source
    │   ├── kvm_qemu/            # QEMU + SeaBIOS with anti-VM patches
    │   └── libvirt/             # libvirt, virbr1 network, apparmor
    ├── cape_host/
    │   ├── dependencies/        # System packages, poetry/uv, postgres, tor, jemalloc
    │   ├── repo/                # Clone CAPEv2, venv, pip install
    │   ├── database/            # PostgreSQL + MongoDB, Alembic migrations
    │   ├── signatures/          # YARA, Suricata, volatility3, CAPA, community.py
    │   ├── config/              # Config files, sudoers, rt_tables, community signatures
    │   ├── systemd/             # systemd unit files, enable services, logrotate
    │   └── optional/            # Tag-gated optional components
    │       ├── nginx/
    │       ├── letsencrypt/
    │       ├── guacamole/
    │       ├── clamav/
    │       ├── fail2ban/
    │       ├── prometheus/
    │       ├── modsecurity/
    │       └── crowdsecurity/
    └── cape_guest/
        ├── os_prep/             # Generate Windows hardening scripts
        ├── agent/               # Generate agent deployment scripts
        └── snapshot/            # Generate snapshot instructions
```

---

## Epic 1: Project Scaffolding and Inventory

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 1.1 | Create Ansible directory layout | `ansible/inventory/`, `ansible/playbooks/`, `ansible/roles/`, `ansible/group_vars/`, `ansible/host_vars/` | None | S | `tree ansible/` shows the full layout; `ansible.cfg` sets `inventory=inventory/hosts.ini`, `roles_path=roles` |
| 1.2 | Write `inventory/hosts.ini` | Define `[cape_host]` and `[cape_guests]` groups with connection vars | 1.1 | S | `ansible-inventory -i inventory/hosts.ini --graph` produces correct group tree |
| 1.3 | Write `group_vars/` files | `cape_host.yml`, `cape_guests.yml`, `all.yml` with deployment_mode | 1.1 | M | `ansible localhost -m debug -a 'var=hostvars["localhost"]'` shows merged vars with correct precedence |
| 1.4 | Create Ansible Vault for secrets | Encrypt `db_password`, `snmp_community`, `vault_*` values | 1.3 | S | `ansible-vault view group_vars/cape_host.yml` decrypts and shows expected keys |
| 1.5 | Create `ansible-deploy.sh` wrapper | Syntax-check → dry-run → confirmation → execution; supports `--tags`, `--limit`, `--skip-tags` | 1.1 | S | `bash ansible-deploy.sh --check --diff` passes syntax check and shows intended changes with zero unexpected destructive actions |
| 1.6 | Write `ansible/README.md` | Usage examples, variable reference, vault instructions, troubleshooting | 1.5 | S | README exists and documents deploy flow, variable overrides, tag-based partial runs |

---

## Epic 2: Hypervisor Installation (KVM + QEMU + Libvirt)

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 2.1 | Role `hypervisor/kvm_qemu` — compile QEMU from source | Download QEMU tarball, apply HW string replacements, configure with `--target-list=...`, `make -j`, package as `.deb`, install with `--force-overwrite` | 1.3 | XL | `qemu-system-x86_64 --version` matches version; `dmesg` inside test VM shows replaced strings |
| 2.2 | Role `hypervisor/kvm_qemu` — compile SeaBIOS from source | Download seabios, apply HW replacements, `make`, copy bios to QEMU firmware dir | 2.1 | L | `strings /usr/share/qemu/bios.bin` shows anti-VM replacement strings |
| 2.3 | Role `hypervisor/libvirt` — compile libvirt from source | Download, `meson setup build -D system=true -D driver_qemu=enabled -D secdriver_apparmor=enabled ...`, `ninja install` | 2.2 | XL | `libvirtd --version` matches version; `systemctl status libvirtd` shows active |
| 2.4 | Role `hypervisor/libvirt` — configure libvirtd | Set unix_sock_group, unix_sock_rw_perms, auth_unix_ro/rw = none, security_driver = apparmor, apparmor complain mode | 2.3 | M | `virsh -c qemu:///system list` succeeds as non-root cape user |
| 2.5 | Role `hypervisor/libvirt` — create virbr1 network | Define persistent virtual network virbr1 192.168.1.0/24, NAT, autostart | 2.4 | M | `virsh net-list --all` shows virbr1 active/autostart; `ip a show virbr1` shows interface up |
| 2.6 | Role `hypervisor/kvm_qemu` — GRUB IOMMU + auto-reboot | Add `intel_iommu=on` to GRUB_CMDLINE_LINUX, `update-grub`; trigger reboot via `ansible.builtin.reboot`; wait for connection via `wait_for_connection`; re-gather facts | 2.2 | M | Post-reboot: cmdline contains `iommu=on`; `virsh list` succeeds; roles resume without manual intervention |

**Handler**: `handlers/main.yml` exposes a `reboot required` listener.

---

## Epic 3: Host Base OS Dependencies and System Tuning

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 3.1 | Role `common` — APT packages | Install all apt deps from cape2.sh `dependencies()` | 1.3 | L | `dpkg -l` shows all required packages installed |
| 3.2 | Role `common` — install poetry or uv | If `use_uv: true`: curl install script → `/usr/local/bin/uv`; else: → `/etc/poetry/bin/poetry` | 3.1 | S | `uv --version` or `poetry --version` succeeds |
| 3.3 | Role `common` — create `cape` user | `groupadd cape`, `useradd --system -g cape -d /home/cape -m cape -s /bin/bash`; add to kvm, libvirt, systemd-journal groups | 1.3 | S | `id cape` shows uid, gid, supplementary groups |
| 3.4 | Role `common` — sysctl and limits | Write `/etc/sysctl.d/99-cape.conf` (file-max, ip_forward, bridge-nf, swappiness, ipv6 disable); write `/etc/security/limits.d/99-cape.conf` (nofile 1048576) | 1.3 | M | `sysctl -a` shows values; `ulimit -n` for cape shows 1048576 |
| 3.5 | Role `common` — locale and timezone | `locale-gen en_US.UTF-8`, `timedatectl set-timezone UTC` | 1.3 | S | `timedatectl` shows UTC; `locale` shows `LANG=en_US.UTF-8` |
| 3.6 | Role `common` — de4dot and .NET | Install mono packages, download de4dot .deb, `dpkg -i` | 3.1 | S | `de4dot --help` returns usage |
| 3.7 | Role `common` — Tor installation | Add Tor apt repo, configure `/etc/tor/torrc` (TransPort, DNSPort, ControlPort, HashedControlPassword) | 3.1 | M | `systemctl is-active tor` shows `active`; ports 9050, 9051, 9040, 5353 listening |

---

## Epic 4: CAPE Core — Repository, Virtual Environment, and Configuration

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 4.1 | Role `repo` — clone CAPEv2 | `git clone` to `{{ cape_root }}`; `chown cape:cape` | 3.2, 3.3 | S | `{{ cape_root }}/.git/HEAD` exists; owner is cape |
| 4.2 | Role `repo` — create venv + sync | If `use_uv`: `uv venv && uv sync`; else: `poetry install` | 4.1 | L | Dependencies resolved; `poetry env list` or `.venv/bin/python` works |
| 4.3 | Role `repo` — install yara-python | `pip install yara-python` in venv (or compile) | 4.2 | M | `python3 -c "import yara; print(yara.__version__)"` succeeds in venv |
| 4.4 | Role `config` — copy and customize configs | `cp conf/default/*.conf.default conf/*.conf`; sed postgresql connection, interface, mongodb reporting toggle | 4.2 | M | Configs contain correct postgresql URI, interface, and mongodb setting |
| 4.5 | Role `config` — download community signatures | `sudo -u cape {{ python_mgr }} run python3 utils/community.py -waf -cr` | 4.4 | L | `{{ cape_root }}/community/` populated with `.yar` and `.pyc` files |
| 4.6 | Role `config` — set up sudoers | Write `/etc/sudoers.d/cape`, `/etc/sudoers.d/ip_netns`, `/etc/sudoers.d/tcpdump` | 3.3 | S | `sudo -l -U cape` shows all expected NOPASSWD entries |
| 4.7 | Role `config` — configure rt_tables | Add `400 {{ internet_iface }}` to `/etc/iproute2/rt_tables` | 3.3 | S | Entry present in rt_tables |

---

## Epic 5: Database Layer — PostgreSQL and MongoDB

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 5.1 | Role `database` — install PostgreSQL | `apt install postgresql`; ensure running + enabled | 3.1 | S | `pg_isready` returns `accepting connections` |
| 5.2 | Role `database` — create PostgreSQL user + DB | `CREATE USER cape WITH PASSWORD '...'`; `CREATE DATABASE cape OWNER cape`; configure pg_hba.conf | 5.1 | S | `psql -U cape -d cape -c "SELECT 1"` succeeds |
| 5.3 | Role `database` — install MongoDB (optional) | Add MongoDB repo per Ubuntu version; `apt install mongodb-org`; enable + start | 3.1 | M | `mongosh --eval "db.version()"` returns version |
| 5.4 | Role `database` — run Alembic migrations | `alembic upgrade head` from `{{ cape_root }}` | 5.2, 4.2 | M | Migration output contains OK; tables exist in PostgreSQL |

---

## Epic 6: Signatures and Detection Engines

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 6.1 | Role `signatures` — compile YARA | Download tarball, `./configure --enable-cuckoo --enable-magic --enable-dotnet`, `make -j`, `make install` | 3.1 | M | `yara --version` prints version; `python3 -c "import yara"` succeeds |
| 6.2 | Role `signatures` — install Suricata | `apt install suricata` (or compile); configure `/etc/suricata/suricata.yaml` with `interface = {{ network_iface }}` | 3.1, 4.4 | M | `suricata --build-info` prints version; `systemctl is-active suricata` shows active |
| 6.3 | Role `signatures` — install volatility3 | `pip install git+https://github.com/volatilityfoundation/volatility3` in venv; download + extract Windows symbols | 4.2 | M | `vol.py -h` succeeds; symbols dir has `.json` files |
| 6.4 | Role `signatures` — install FLARE CAPA | `pip install flare-capa` in venv | 4.2 | S | `capa --version` prints version |
| 6.5 | Role `signatures` — schedule crontab | Daily `community.py -waf -cr` + `pip install -U flare-capa`; hourly Tor newnym rotation | 4.1 | S | `crontab -u cape -l` shows both entries |

---

## Epic 7: Systemd Services and Monitoring

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 7.1 | Role `systemd` — copy unit files | `cp systemd/*.service /lib/systemd/system/` from `{{ cape_root }}` | 4.1 | S | All `.service` files present in `/lib/systemd/system/` |
| 7.2 | Role `systemd` — customize unit paths | If `cape_root != /opt/CAPEv2`: sed paths; if `use_uv`: replace poetry → uv, remove ExecStartPre | 7.1 | M | `grep ExecStart /lib/systemd/system/cape.service` shows correct paths |
| 7.3 | Role `systemd` — enable and start services | `daemon-reload`; enable+start: cape, cape-rooter, cape-processor, cape-web (if mongo), suricata; conditional: cape-fstab, cape-pubsub, cape-dist | 7.2 | M | `systemctl is-active cape` = `active`; all enabled services show `enabled` |
| 7.4 | Role `systemd` — install logrotate | Write `/etc/logrotate.d/cape` for `{{ cape_root }}/storage/` logs | 1.3 | S | `logrotate -d /etc/logrotate.d/cape` exits 0 |
| 7.5 | Role `systemd` — install jemalloc | `apt install libjemalloc-dev`; configure LD_PRELOAD in systemd units | 3.1 | S | `LD_PRELOAD=libjemalloc.so python3 ...` works |

---

## Epic 8: Optional Components (All Included, Tag-Gated)

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 8.1 | Role `nginx` — compile + configure | Download nginx + pcre2 + openssl + zlib, compile with modules, create .deb, install; configure bot-blocker, Cloudflare cert, systemd, logrotate | 3.1 | XL | `nginx -V` shows modules; `systemctl is-active nginx` shows active |
| 8.2 | Role `letsencrypt` — certificate | Install certbot, `certbot --nginx -d {{ domain }}` | 8.1 | S | `certbot certificates` shows valid cert |
| 8.3 | Role `guacamole` — Apache Guacamole | Install guacd, deploy guacd.service + guac-web.service | 3.1 | L | Web browser connects via Guacamole to guest VM |
| 8.4 | Role `clamav` — ClamAV | `apt install clamav-daemon clamav-unofficial-sigs`; configure unofficialsigs, apparmor; enable+start | 3.1 | M | `clamscan --version` works; `systemctl is-active clamav-daemon` |
| 8.5 | Role `fail2ban` — brute-force protection | `apt install fail2ban`; configure jails for ssh, nginx, cape-web | 1.3 | S | `fail2ban-client status` shows active jails |
| 8.6 | Role `prometheus` — monitoring | Download prometheus + grafana, install, configure datasource; node_exporter on workers | 1.3 | L | Prometheus web UI accessible; Grafana dashboard loads |
| 8.7 | Role `modsecurity` — WAF | Compile ModSecurity v3, build as nginx dynamic module, configure OWASP CRS | 8.1 | L | ModSecurity audit log written on rule match |
| 8.8 | Role `crowdsecurity` — IPS | Install crowdsec, add nginx collection, install nginx bouncer | 8.1 | M | `cscli metrics` shows parsed logs |

---

## Epic 9: Guest VM Provisioning (Manual Scripts)

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 9.1 | Role `os_prep` — generate hardening script | Template `.ps1` from win10_disabler.ps1 + disable_win7noise.bat; write to `generated_guest_scripts/harden.ps1` and `harden.bat` with SHA256 output | 1.3 | M | Scripts exist, valid PowerShell; dry-run produces no changes on controller |
| 9.2 | Role `os_prep` — generate dependency installer | Template `.ps1` that downloads/installs Python 3.x, VC++ redist, pip packages; write to `generated_guest_scripts/install_deps.ps1` | 9.1 | S | Script idempotent: checks versions before install |
| 9.3 | Role `agent` — generate agent deploy script | Template `.ps1` to copy agent files, register as Windows service (`New-Service`), test TCP connection to host:8000; generates paired `uninstall_agent.ps1` | 9.2 | M | Script creates rollback `.ps1` alongside deploy script |
| 9.4 | Role `agent` — generate agent config | Template `config.ini` with resultserver_ip, port, machine_name; write to `generated_guest_scripts/config.ini` | 9.3 | S | Config contains correct IP:port for host result server |
| 9.5 | Role `snapshot` — generate instructions doc | Write `generated_guest_scripts/SNAPSHOT_INSTRUCTIONS.md` with step-by-step: transfer scripts → run in order → shutdown → libvirt snapshot → update kvm.conf | 9.4 | S | Instructions exist referencing exact file paths and commands |

---

## Epic 10: Validation, Smoke Tests, and Documentation

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 10.1 | Write `verify.yml` playbook | Post-deploy checks: systemd services active, PostgreSQL accepts cape, MongoDB responds, YARA version, Suricata on correct iface, Tor ports listening, KVM VM defined, result server (8000) listening, web UI responds | All | L | `ansible-playbook verify.yml` exits 0 with all checks green |
| 10.2 | Integration smoke test | Submit benign file via REST API, poll for completion (<5 min), verify report has expected fields | All | XL | Report JSON contains `file_name`, `"status": "reported"`, at least one signature or network entry |
| 10.3 | Generate `ansible/README.md` | Document inventory, required vars, vault, playbook commands (full + by tag), guest workflow, troubleshooting | All | S | README peer-reviewed, covers all documented commands |
| 10.4 | Write `rollback.yml` playbook | Reverse every role change: stop services, remove packages, delete users, drop DBs, uninstall compiled software, revert sysctl | All | L | Running after full deploy leaves system clean for re-deployment |

---

## Epic 11: Multi-Node Orchestration

| # | Task | Description | Deps | Complexity | Definition of Done |
|---|---|---|---|---|---|
| 11.1 | Write `multi-node-web.yml` | Playbook for `cape_web` group: web interface, nginx, MongoDB client, cape-web only; no processing/signatures | 4.4, 5.3 | M | Web UI accessible; no processing running on web node |
| 11.2 | Write `multi-node-worker.yml` | Playbook for `cape_worker` group: processing, signatures, suricata, yara, cape-processor, cape-dist; configures remote result server back to control | 4.1, 4.4, 5.2 | M | Worker processes tasks from control; procmon log shows `connected to cape-master` |
| 11.3 | Update `site.yml` for multi-node | If `deployment_mode == 'multi'`: skip services on wrong nodes; per-group via `import_playbook` | 11.x | L | Each node group only enables appropriate services |
| 11.4 | Write `register-worker.yml` | On control node, register worker SSH key, distribute DB connection string, verify worker can reach PostgreSQL | 11.2 | S | Worker's `cuckoo.conf` connects to control PostgreSQL |

---

## Dependency DAG

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
                 └── Epic 11 (Multi-node) [if deployment_mode=multi]
```

---

## Complexity Legend

| Label | Meaning |
|---|---|
| **S** | 1–2 tasks, no branching, standard Ansible modules |
| **M** | 3–5 tasks, conditionals, some compiled-from-source or shell-out |
| **L** | 6–10 tasks, multi-step source compilation, interdependent changes |
| **XL** | Full role with cross-resource dependencies, HW patching, multi-platform |

---

## Key Design Decisions

| # | Decision | Implementation |
|---|---|---|
| 1 | Auto-reboot after GRUB IOMMU change | `ansible.builtin.reboot` + `wait_for_connection` in handler; no manual reboot needed |
| 2 | Guest provisioning via manual scripts | All guest tasks generate `.ps1`/`.bat` files under `generated_guest_scripts/`; no WinRM requirement |
| 3 | All optional components included by default | All Epic 8 roles in default run path; skippable via `--skip-tags optional` |
| 4 | Single-node and multi-node modes | `deployment_mode` var; inventory groups `[cape_control]`, `[cape_web]`, `[cape_worker]`; separate playbooks per node type |
| 5 | Idempotency | Every task uses idempotent modules; compiled-from-source checks binary presence + version before recompile |
| 6 | Rollback support | Dedicated `rollback.yml`; compiled software installed as `.deb`; uninstall scripts paired with guest deploy scripts |

---

## Improvement Plan (Post-Epic Analysis) — ✅ Complete

All items implemented and committed on `feat/ansible-playbook`.

### Bug Fixes (Critical — may break at runtime)

| # | Issue | File | Fix Commit | Status |
|---|-------|------|------------|--------|
| 1 | Rollback confirmation always fails | `playbooks/rollback.yml` | `193af6e4` | ✅ |
| 2 | `control_pubkey` doesn't persist across playbook runs | `playbooks/register-worker.yml` | `1349fd41` | ✅ |
| 3 | YAML literal block `\|` in meson configure | `roles/hypervisor/libvirt/tasks/main.yml` | `9b991c3d` | ✅ |
| 4 | `$BXPC_REPLACER` bash variable undefined | `roles/hypervisor/kvm_qemu/tasks/seabios.yml` | `cd66e00f` | ✅ |
| 5 | Hardcoded `intel_iommu=on` breaks AMD | `roles/hypervisor/kvm_qemu/tasks/iommu.yml` | `6768b560` | ✅ |
| 6 | Worker can't access `hostvars` from `cape_control` | `playbooks/register-worker.yml` | `a0e5a10e` | ✅ |

### Bug Fixes (High — may break under edge conditions)

| # | Issue | File | Fix Commit | Status |
|---|-------|------|------------|--------|
| 7 | `cscli hub delete` syntax wrong — removed (dpkg handles cleanup) | `playbooks/rollback.yml` | `d9cd5622` | ✅ |
| 8 | `openssl dhparam` fails — parent `/etc/nginx/cert/` missing | `roles/cape_host/tasks/optional.yml` | `d9cd5622` | ✅ |
| 9 | ModSecurity `v3/master` invalid git ref → `v3.0.12` | `roles/cape_host/tasks/optional.yml` | `d9cd5622` | ✅ |
| 10 | Crowdsec wizard interactive — added `-n` flag | `roles/cape_host/tasks/optional.yml` | `d9cd5622` | ✅ |

### Idempotency Gaps (runs every time) — ✅

| # | Issue | File | Fix |
|---|-------|------|-----|
| 1 | Git clone as root → `become_user: cape` | `roles/cape_host/tasks/repo.yml` | Added `become_user` |
| 2 | `uv sync` / `poetry install` no creates guard | `roles/cape_host/tasks/repo.yml` | (skipped — fast no-ops with lock files) |
| 3 | Config loop clobbers every run | `roles/cape_host/tasks/config.yml` | Added `[ -f dest ] \|\| cp` guard |
| 4 | YARA compile no guard | `roles/cape_host/tasks/signatures.yml` | Version check + `when: yara_needs_build` |
| 5 | nginx build no guard | `roles/cape_host/tasks/optional.yml` | Version check + block guard |
| 6 | Modsecurity build no guard | `roles/cape_host/tasks/optional.yml` | `stat` module check |
| 7 | `logrotate --force` runs every time | `roles/cape_host/tasks/systemd.yml` | Replaced with normal logrotate |

### Missing Features vs cape2.sh (17 gaps) — ✅

All added to `roles/cape_host/tasks/optional_extra.yml`, gated by variables (all default `false` except `disable_unattended_upgrades` and `smtp_sinkhole_enable`). Commit: `86e82a87`.

| # | Feature | Variable | Notes |
|---|---------|----------|-------|
| 1 | Elasticsearch | `elasticsearch_enable` | APT repo + install |
| 2 | fluentd | `fluentd_enable` | Google logging agent |
| 3 | mitmproxy | `mitmproxy_enable` | Download + wrapper |
| 4 | PolarProxy | `polarproxy_enable` | Download + extract |
| 5 | passiveDNS | `passivedns_enable` | Compile from source + `.deb` |
| 6 | redsocks2 | `redsocks2_enable` | Compile from source |
| 7 | Docker | `docker_enable` | Official repo + install |
| 8 | DIE | `die_enable` | `.deb` from GitHub |
| 9 | Yara-X | `yarax_enable` | Rust + `cargo install` |
| 10 | IntroVirt | `introvirt_enable` | Download release tarball |
| 11 | Distributed | `distributed_enable` | uwsgi + flask + DB |
| 12 | IDAPython/Ghidra | `re_frameworks_enable` | pip install |
| 13 | SSH authkeys | `ssh_authkeys_enable` | `authorized_key` module |
| 14 | SNMP config | `snmp_enable` | snmpd.conf + extend scripts |
| 15 | LibreNMS | `librenms_enable` | Agent scripts + crontab |
| 16 | Disable unattended-upgrades | `disable_unattended_upgrades` | `lineinfile` (default: true) |
| 17 | SMTP sinkhole @reboot | `smtp_sinkhole_enable` | `cron` special_time (default: true) |

### Structural Improvements — ✅

| # | Suggestion | File | Fix Commit | Status |
|---|-----------|------|------------|--------|
| 1 | Add `deployment_mode` assert | `site.yml` | `ce8c028b` | ✅ |
| 2 | Add `--list-tags` to deploy script | `ansible-deploy.sh` | `ce8c028b` | ✅ |
| 3 | Unique tags for hypervisor sub-tasks | `roles/hypervisor/tasks/main.yml` | (already had unique tags) | ✅ |
| 4 | Deduplicate python3-dev/python3-pip | `roles/common/tasks/dependencies.yml` | `ce8c028b` | ✅ |
| 5 | BBR kernel version check via modprobe | `roles/common/tasks/sysctl.yml` | `ce8c028b` | ✅ |
| 6 | MongoDB AVX via `ansible_processor_flags` | `roles/cape_host/tasks/database.yml` | `ce8c028b` | ✅ |
| 7 | `callback_whitelist` → `callbacks_enabled` | `ansible.cfg` | `ce8c028b` | ✅ |
| 8 | Add `forks=20`, `gather_timeout=60` | `ansible.cfg` | `ce8c028b` | ✅ |
| 9 | Fix stale `hosts.ini` comment | `inventory/hosts.ini` | `ce8c028b` | ✅ |
| 10 | `tor_socket_timeout` int not string | `group_vars/all/vars.yml` | `ce8c028b` | ✅ |
