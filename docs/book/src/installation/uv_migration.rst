.. _uv_migration:

===============================================
Migrating CAPE Infrastructure from Poetry to uv
===============================================

CAPEv2 uses `uv <https://docs.astral.sh/uv/>`_ with a ``uv``-managed **Python 3.14**
runtime (pinned via ``.python-version``) instead of Poetry and the host OS Python.

Why migrate
===========

* **Decouples CAPE from the host OS Python**: Ubuntu 22.04 ships Python 3.10 (EOL October 2026).
  ``uv`` downloads a standalone CPython 3.14 build into ``/usr/local/share/uv/python`` without
  modifying system ``/usr/bin/python3`` or ``apt`` packages.
* **Security coverage**: Several core dependencies (``Pillow>=13``, ``filelock>=4.2.1``,
  ``soupsieve>=4``, ``dnspython>=2.9``, ``autobahn>=26.7``) only ship CVE fixes for
  Python 3.11.5+. Running CAPE on ``uv``-managed Python 3.14 lets every deployment stay on
  patched releases regardless of host distro.
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

1. Saves the list of currently enabled ``cape*`` / ``guac-web`` services and stops them.
2. Snapshots the existing Poetry environment to ``/tmp/cape-poetry-freeze.txt`` (if Poetry is
   present) so optional extras (``gcp``, ``s3``, ``azure``, ``yara``, ``mcp``, ``dist``) and
   packages (``libvirt-python``, ``yara-python``, ``volatility3``) are detected.
3. Installs ``uv`` to ``/usr/local/bin/uv`` and standalone Python 3.14 to
   ``/usr/local/share/uv/python`` (world-readable so both ``cape`` and ``root`` services share
   one interpreter).
4. Creates ``$CAPE_ROOT/.venv`` on Python 3.14 owned by ``cape`` and runs
   ``uv sync --locked --no-install-project --inexact``.
5. Rebuilds native extensions (``libvirt-python``, ``yara-python`` with cuckoo/magic/profiling)
   and reinstalls ``volatility3`` if previously present.
6. Updates installed systemd units in ``/lib/systemd/system/`` from Poetry to
   ``/usr/local/bin/uv run --no-sync``, updates root crontab Poetry commands, reloads systemd,
   and restarts the previously enabled services.
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
    sudo -u cape env UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python \
        /usr/local/bin/uv venv --python 3.14 /opt/CAPEv2/.venv

    # Base dependencies (add --extra / --group flags matching your deployment)
    sudo -u cape env UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python \
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
   removes packages installed via ``uv pip install`` (such as ``libvirt-python``, custom-built
   ``yara-python``, ``volatility3``, and ``extra/optional_dependencies.txt``).

5. Reinstall native & optional packages
---------------------------------------

Inspect ``/tmp/cape-poetry-freeze.txt`` and reinstall any host-built or optional packages into
``/opt/CAPEv2/.venv``:

.. code-block:: bash

    # libvirt-python (KVM hosts — match installed libvirt version)
    PKG_CONFIG_PATH="$(dirname "$(locate libvirt.pc | head -n1)")"
    sudo -u cape env PKG_CONFIG_PATH="$PKG_CONFIG_PATH" \
        /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python libvirt-python==11.9.0

    # yara-python built with CAPE's required flags
    sudo -u cape /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python yara-python \
        --no-binary :all: \
        --config-setting="--global-option=build" \
        --config-setting="--global-option=--enable-cuckoo" \
        --config-setting="--global-option=--enable-magic" \
        --config-setting="--global-option=--enable-profiling"

    # Optional: extra dependencies and Volatility 3 (only if used in your deployment)
    sudo -u cape /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python -r extra/optional_dependencies.txt
    sudo -u cape /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python git+https://github.com/volatilityfoundation/volatility3

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
     - ``/usr/local/bin/uv run --no-sync python manage.py runserver_plus 0.0.0.0:8000 --traceback --keep-meta-shutdown`` (or Gunicorn below)
   * - ``cape-rooter.service``
     - Remove ``ExecStartPre=...poetry config cache-dir...``; set ``ExecStart=/usr/local/bin/uv run --no-sync python rooter.py -g cape``
   * - ``cape-fstab.service``
     - Remove ``ExecStartPre=...poetry config cache-dir...``; set ``ExecStart=/usr/local/bin/uv run --no-sync python fstab.py -g cape``
   * - ``cape-dist.service``
     - ``/usr/local/bin/uv run --no-sync python dist.py -ef``
   * - ``cape-sigma-update.service``
     - ``/usr/local/bin/uv run --no-sync --project /opt/CAPEv2 python zircolite.py --update-rules``
   * - ``guac-web.service``
     - ``/usr/local/bin/uv run --no-sync gunicorn --bind 127.0.0.1:8008 web.asgi -t 180 -w 4 -k uvicorn.workers.UvicornWorker --capture-output --enable-stdio-inheritance``
   * - ``cape-pubsub.service``
     - ``/usr/local/bin/uv run --no-sync python utils/gcp_pubsub_service.py``

Reload systemd and start the services:

.. code-block:: bash

    sudo systemctl daemon-reload
    xargs -r sudo systemctl start < /tmp/cape-enabled-services.txt

7. Web UI behind Nginx: uWSGI vs Gunicorn
-----------------------------------------

.. warning::

   The distro package ``uwsgi-plugin-python3`` is compiled against the **host OS**
   ``libpython`` (for example Python 3.10 on Ubuntu 22.04 or 3.12 on Ubuntu 24.04) and
   **cannot** load a ``uv``-managed Python 3.14 ``.venv``.

If you previously served Django via system ``uwsgi``, switch ``cape-web.service`` to Gunicorn
running inside ``uv`` (Gunicorn is included in ``pyproject.toml``):

.. code-block:: ini

    [Service]
    WorkingDirectory=/opt/CAPEv2/web
    ExecStart=/usr/local/bin/uv run --no-sync gunicorn web.wsgi -b 127.0.0.1:8000 -w 4 -t 200 --capture-output --enable-stdio-inheritance
    User=cape
    Group=cape

Alternatively, if you require uWSGI, build ``uwsgi`` directly inside ``.venv`` so it links
against the ``uv``-managed Python 3.14 library:

.. code-block:: bash

    sudo -u cape /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python uwsgi

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
    sudo -u cape /usr/local/bin/uv --directory /opt/CAPEv2 run --no-sync python --version

    # 2. Confirm native extensions import cleanly
    sudo -u cape /usr/local/bin/uv --directory /opt/CAPEv2 run --no-sync python -c "import yara, libvirt, django, sqlalchemy; print('OK')"

    # 3. Confirm all services are active and check recent logs
    systemctl status cape cape-processor cape-rooter cape-web --no-pager
    journalctl -u cape -u cape-processor -u cape-rooter -u cape-web -n 50 --no-pager

    # 4. Run a smoke submission and verify processing + web UI report rendering

Cleaning Up Poetry (After Verification)
=======================================

Once all services and test submissions succeed, remove the old Poetry installation and caches:

.. code-block:: bash

    sudo rm -rf /etc/poetry /opt/CAPEv2/.cache/pypoetry /home/cape/.cache/pypoetry /root/.cache/pypoetry
    sudo sed -i '/\/etc\/poetry\/bin/d' /etc/bash.bashrc
