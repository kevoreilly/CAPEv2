.. _uv_migration:

===============================================
Migrating CAPE Infrastructure from Poetry to uv
===============================================

CAPEv2 uses `uv <https://docs.astral.sh/uv/>`_ with a ``uv``-managed **Python 3.14**
runtime (pinned via ``.python-version``) instead of Poetry and the host OS Python.

Why migrate
===========

* **Decouples CAPE from the host OS Python**: Ubuntu 22.04 ships Python 3.10 (EOL October 2026).
  ``uv`` downloads a standalone CPython 3.14 build (security support through October 2030) into
  ``/usr/local/share/uv/python`` without modifying system ``/usr/bin/python3`` or ``apt`` packages.
* **Security coverage**: The recent wave of AI-assisted vulnerability discovery has accelerated
  CVE volume across core Python packages, and upstream security fixes for several dependencies
  (``Pillow>=13``, ``filelock>=4.2.1``, ``soupsieve>=4``, ``dnspython>=2.9``) require
  Python 3.11.5+. Running CAPE on an independent, ``uv``-managed Python 3.14 runtime lets every
  deployment stay on patched releases regardless of host distro.
* **Single lockfile & faster syncs**: ``uv.lock`` replaces ``poetry.lock`` and installs in
  seconds with deterministic hashes.
* **Safe service startups**: Systemd units invoke ``/usr/local/bin/uv run --no-sync``, so
  restarts never mutate ``.venv`` or require internet access (including root-owned services
  such as ``cape-rooter`` and ``cape-fstab``).

.. note::

   This migration applies to the **CAPE host** (main server, processors, workers, web UI,
   and distributed server). Windows guest VMs running ``agent/agent.py`` are unaffected.

Option 1: Automated Migration (Single Host)
===========================================

On an existing CAPEv2 host installed via ``installer/cape2.sh``:

.. code-block:: bash

    cd /opt/CAPEv2
    sudo -u cape git pull
    sudo bash installer/cape2.sh migrate-uv | tee migrate-uv.log

For a custom install directory:

.. code-block:: bash

    sudo CAPE_ROOT=/mnt/sandbox/CAPEv2 bash installer/cape2.sh migrate-uv | tee migrate-uv.log

What ``migrate-uv`` does:

1. Saves the list of currently enabled ``cape*`` / ``guac-web`` services/timers and stops them.
2. Snapshots the existing Poetry environment to ``/tmp/cape-poetry-freeze.txt`` (if Poetry is
   present) so optional extras (``gcp``, ``s3``, ``azure``, ``yara``, ``mcp``, ``dist``) and
   packages (``libvirt-python``, ``volatility3``) are detected.
3. Installs ``uv`` to ``/usr/local/bin/uv`` and standalone Python 3.14 to
   ``/usr/local/share/uv/python`` (world-readable so both ``cape`` and ``root`` services share
   one interpreter).
4. Creates ``$CAPE_ROOT/.venv`` on Python 3.14 owned by ``cape`` and runs
   ``uv sync --locked --no-install-project --inexact``.
5. Installs ``yara-x`` (prebuilt wheel), rebuilds ``libvirt-python`` (on KVM hosts), and
   reinstalls ``volatility3`` if previously present.
6. Seeds missing ``conf/*.env`` files from ``conf/default/*.env.default``, updates installed
   systemd units in ``/lib/systemd/system/`` (and ``/etc/systemd/system/``) to
   ``/usr/local/bin/uv run --no-sync``, updates root and ``cape`` crontab Poetry commands,
   reloads systemd, and restarts the previously enabled services.
7. Leaves ``/etc/poetry`` and old Poetry virtualenvs untouched until you verify and clean up.

Option 2: Manual / Fleet Migration (Ansible, Custom Infra, Distributed Nodes)
=============================================================================

Follow these steps on each node (start with one worker, verify a task end-to-end, then roll
out to remaining workers and the main/web server).

1. Snapshot current Poetry packages & stop services
---------------------------------------------------

.. code-block:: bash

    # Record installed packages and custom extras before switching
    sudo -u cape /etc/poetry/bin/poetry --directory /opt/CAPEv2 run pip freeze > /tmp/cape-poetry-freeze.txt

    # Record enabled services and stop them
    systemctl list-unit-files "cape*" "guac-web*" --state=enabled --no-legend | awk '{print $1}' > /tmp/cape-enabled-services.txt
    sudo systemctl stop "cape*" guac-web 2>/dev/null || true

2. Pull latest CAPEv2
---------------------

.. code-block:: bash

    cd /opt/CAPEv2
    sudo -u cape git pull

3. Install ``uv`` and shared Python 3.14
----------------------------------------

Install ``uv`` system-wide and place the managed Python 3.14 build in a shared world-readable
directory so both ``cape`` services and root-owned services (``cape-rooter``, ``cape-fstab``)
use the same interpreter without duplicate downloads:

.. code-block:: bash

    curl -LsSf https://astral.sh/uv/install.sh | sudo env UV_INSTALL_DIR=/usr/local/bin sh
    sudo mkdir -p /usr/local/share/uv/python
    sudo env UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python /usr/local/bin/uv python install 3.14
    sudo chmod -R a+rX /usr/local/share/uv/python

    # Persist shared Python directory for interactive shells
    echo 'export UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python' | sudo tee /etc/profile.d/uv-cape.sh >/dev/null

Verify:

.. code-block:: bash

    /usr/local/bin/uv --version
    UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python /usr/local/bin/uv python find 3.14

4. Create ``.venv`` and sync dependencies
-----------------------------------------

Run as the ``cape`` user (never as ``root``, which breaks ``.venv`` ownership):

.. code-block:: bash

    cd /opt/CAPEv2
    sudo -Hu cape env UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python \
        /usr/local/bin/uv venv --python 3.14 /opt/CAPEv2/.venv

    # Base dependencies (add --extra / --group flags matching your deployment)
    sudo -Hu cape env UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python \
        /usr/local/bin/uv sync --locked --no-install-project --inexact --python 3.14

Include optional extras or dependency groups as needed:

* Distributed API server (``utils/dist.py``): add ``--group dist``
* GCS reporting / object storage: add ``--extra gcp``
* S3 / MinIO object storage: add ``--extra s3``
* Azure Blob / machinery: add ``--extra azure``
* YARA parser (``plyara``): add ``--extra yara``
* MCP server: add ``--extra mcp``

.. important::

   Always pass ``--inexact`` to ``uv sync`` on CAPE hosts. Without ``--inexact``, ``uv sync``
   removes packages installed via ``uv pip install`` (such as ``libvirt-python``, ``yara-x``,
   ``volatility3``, and ``extra/optional_dependencies.txt``).

5. Reinstall native & optional packages
---------------------------------------

Inspect ``/tmp/cape-poetry-freeze.txt`` and reinstall any host-built or optional packages into
``/opt/CAPEv2/.venv``:

.. code-block:: bash

    # libvirt-python (KVM hosts — match the host libvirt version from libvirt.pc;
    # install libvirt-dev pkg-config first if libvirt.pc is missing on distro KVM hosts)
    PKG_CONFIG_PATH="$(dirname "$(find /usr/local/lib64 /usr/lib64 /usr/local/lib /usr/lib -maxdepth 4 -name 'libvirt.pc' 2>/dev/null | head -n1)")"
    LIBVIRT_VER="$(PKG_CONFIG_PATH="$PKG_CONFIG_PATH" pkg-config --modversion libvirt)"
    sudo -Hu cape env PKG_CONFIG_PATH="$PKG_CONFIG_PATH" \
        /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python "libvirt-python==${LIBVIRT_VER}" \
        || sudo -Hu cape env PKG_CONFIG_PATH="$PKG_CONFIG_PATH" \
        /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python "libvirt-python<=${LIBVIRT_VER}"

    # yara-x (prebuilt wheel with cuckoo module included; note YARA-X does not provide
    # the legacy `magic` module — use `sudo bash installer/cape2.sh yara` if needed)
    sudo -Hu cape /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python yara-x

    # Optional: extra dependencies and Volatility 3 (only if used in your deployment)
    sudo -Hu cape /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python -r extra/optional_dependencies.txt
    sudo -Hu cape /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python git+https://github.com/volatilityfoundation/volatility3

6. Update systemd service units
-------------------------------

Copy the updated unit files from ``/opt/CAPEv2/systemd/`` (or apply the equivalent changes in
your Ansible/Puppet templates):

.. list-table:: Systemd ExecStart changes
   :header-rows: 1
   :widths: 28 72

   * - Unit
     - New ``ExecStart`` (and removed lines)
   * - ``cape.service``
     - ``/usr/local/bin/uv run --no-sync python cuckoo.py``
   * - ``cape-processor.service``
     - ``/usr/local/bin/uv run --no-sync python utils/process.py``
   * - ``cape-web.service``
     - ``/usr/local/bin/uv run --no-sync granian --interface wsgi --no-ws --respawn-failed-workers --access-log --process-name cape-web --static-path-route /static --static-path-mount /opt/CAPEv2/web/static_collected web.wsgi:application`` (runs ``manage.py collectstatic --noinput`` in ``ExecStartPre``; tune via ``conf/cape-web.env``)
   * - ``cape-rooter.service``
     - Remove ``ExecStartPre=...poetry config cache-dir...``; set ``ExecStart=/usr/local/bin/uv run --no-sync python rooter.py -g cape``
   * - ``cape-fstab.service``
     - Remove ``ExecStartPre=...poetry config cache-dir...``; set ``ExecStart=/usr/local/bin/uv run --no-sync python fstab.py -g cape``
   * - ``cape-dist.service``
     - ``/usr/local/bin/uv run --no-sync python dist.py -ef``
   * - ``cape-sigma-update.service``
     - ``/usr/local/bin/uv run --no-sync --project /opt/CAPEv2 python zircolite.py --update-rules``
   * - ``guac-web.service``
     - ``/usr/local/bin/uv run --no-sync granian --interface asgi --ws --respawn-failed-workers --access-log --process-name guac-web web.asgi:application`` (tune via ``conf/guac-web.env``)
   * - ``cape-pubsub.service``
     - ``/usr/local/bin/uv run --no-sync python utils/gcp_pubsub_service.py``

Reload systemd and start the services:

.. code-block:: bash

    sudo systemctl daemon-reload
    xargs -r sudo systemctl start < /tmp/cape-enabled-services.txt

7. Web UI behind Nginx: Replacing uWSGI / Gunicorn with Granian
-----------------------------------------------------------------

.. warning::

   ``uWSGI`` (``uwsgi-plugin-python3``) has been removed. The distro plugin links against host
   OS ``libpython`` and cannot load a ``uv``-managed Python 3.14 ``.venv``.

``cape-web.service`` (Django WSGI) and ``guac-web.service`` (Channels ASGI WebSockets) now run
on **Granian** with built-in worker respawn, RSS/lifetime recycling, access logging, and
zero-downtime ``SIGHUP`` reloads (``sudo systemctl reload cape-web``).

If you previously ran system ``uwsgi`` behind Nginx:

1. Disable legacy uWSGI configs and stop ``uwsgi``:

   .. code-block:: bash

       sudo rm -f /etc/uwsgi/apps-enabled/*cape*
       sudo systemctl disable --now uwsgi 2>/dev/null || true

2. Bind Granian to loopback in ``/opt/CAPEv2/conf/cape-web.env`` (or ``custom/conf/cape-web.env``):

   .. code-block:: ini

       GRANIAN_HOST=127.0.0.1
       GRANIAN_PORT=8000
       GRANIAN_WORKERS=4
       GRANIAN_BLOCKING_THREADS=4

3. Update Nginx to use HTTP ``proxy_pass`` to ``127.0.0.1:8000`` (and WebSocket ``proxy_pass``
   for ``/guac/`` to ``127.0.0.1:8008``) instead of ``uwsgi_pass`` / ``include uwsgi_params``
   (see ``nginx/cape.conf``), then enable ``cape-web.service``.

8. Update cron jobs, scripts, and monitoring
--------------------------------------------

Check both ``root`` and ``cape`` crontabs (``sudo crontab -l`` and ``sudo -u cape crontab -l``)
and replace Poetry invocations:

.. list-table:: Command mapping (Poetry to uv)
   :header-rows: 1
   :widths: 45 55

   * - Old Poetry command
     - New ``uv`` command
   * - ``poetry install``
     - ``uv sync --locked --no-install-project --inexact``
   * - ``poetry install --extras gcp``
     - ``uv sync --locked --no-install-project --inexact --extra gcp``
   * - ``poetry install --with dist``
     - ``uv sync --locked --no-install-project --inexact --group dist``
   * - ``poetry run python <script.py>``
     - ``uv run --no-sync python <script.py>``
   * - ``poetry --directory /opt/CAPEv2 run python <script.py>``
     - ``uv run --no-sync --project /opt/CAPEv2 python <script.py>``
   * - ``poetry run pip install <pkg>``
     - ``uv pip install --python /opt/CAPEv2/.venv/bin/python <pkg>``
   * - ``poetry env list --full-path``
     - ``/opt/CAPEv2/.venv`` (always fixed in-project)

Verification Checklist
======================

Run these checks after restarting services:

.. code-block:: bash

    # 1. Confirm Python 3.14 inside .venv
    sudo -Hu cape /usr/local/bin/uv --directory /opt/CAPEv2 run --no-sync python --version

    # 2. Confirm native extensions import cleanly
    sudo -Hu cape /usr/local/bin/uv --directory /opt/CAPEv2 run --no-sync python -c "import yara_x, libvirt, django, sqlalchemy; print('OK')"

    # 3. Confirm all services are active and check recent logs
    systemctl status cape cape-processor cape-rooter cape-web --no-pager
    journalctl -u cape -u cape-processor -u cape-rooter -u cape-web -n 50 --no-pager

    # 4. Run a smoke submission and verify processing + web UI report rendering

Troubleshooting
===============

``Failed to connect socket to '/var/run/libvirt/virtqemud-sock'``
-----------------------------------------------------------------

If ``cape.service`` fails immediately after ``migrate-uv`` restarts services with::

    libvirt: XML-RPC error : Failed to connect socket to '/var/run/libvirt/virtqemud-sock': No such file or directory
    CRITICAL: CuckooStartupError: Failed to connect to libvirt with DSN 'qemu:///system'. Error: Failed to connect socket to '/var/run/libvirt/virtqemud-sock': No such file or directory

the cause is usually the host libvirt systemd units rather than the ``uv`` / ``libvirt-python`` build. While ``migrate-uv`` stops CAPE services to install Python 3.14 and rebuild ``libvirt-python``, an idle monolithic ``libvirtd.service`` without ``libvirtd.socket`` enabled exits after 120 seconds (``--timeout 120``) and removes ``/var/run/libvirt/libvirt-sock``, or conflicting monolithic (``libvirtd``) and modular (``virtqemud``) units prevent either socket from starting.

Enable **one** daemon mode on the KVM host (see :ref:`troubleshooting_libvirt_socket` for details):

**Option A — Modular daemons (libvirt 11+ default):**

.. code-block:: bash

    sudo systemctl daemon-reload
    sudo systemctl disable --now libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket 2>/dev/null || true
    sudo systemctl enable --now virtqemud.socket virtqemud-ro.socket virtqemud-admin.socket virtnetworkd.socket virtstoraged.socket virtlogd.socket virtqemud.service

**Option B — Monolithic ``libvirtd``:**

.. code-block:: bash

    sudo systemctl daemon-reload
    sudo systemctl disable --now virtqemud.service virtqemud.socket virtqemud-ro.socket virtqemud-admin.socket virtnetworkd.service virtnetworkd.socket virtstoraged.service virtstoraged.socket 2>/dev/null || true
    sudo systemctl enable --now libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket virtlogd.socket libvirtd.service

Then verify socket access and restart CAPE:

.. code-block:: bash

    ls -la /var/run/libvirt/
    sudo -u cape virsh -c qemu:///system list --all
    sudo systemctl restart cape

Cleaning Up Poetry (After Verification)
=======================================

Once all services and test submissions succeed, remove the old Poetry installation and caches:

.. code-block:: bash

    sudo rm -rf /etc/poetry /opt/CAPEv2/.cache/pypoetry /home/cape/.cache/pypoetry /root/.cache/pypoetry
    sudo sed -i '/\/etc\/poetry\/bin/d' /etc/bash.bashrc
