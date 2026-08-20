============================================
Docker Multi-Container for Extra Info Tools
============================================

This guide explains how to configure, deploy, and secure the modular multi-container Docker architecture for CAPEv2's ``file_extra_info`` static analysis and extraction tools (e.g., ``innoextract``, ``7z``, ``upx``, etc.).

---------------------
Architecture Overview
---------------------

Instead of running vulnerable file extraction utilities directly on the host or compiling them all into one massive monolithic container, this architecture runs each tool inside its own **isolated, lightweight, network-less micro-container**.

.. code-block:: text

                           +---------------------------------------+
                           |             CAPEv2 Host               |
                           +---------------------------------------+
                                               |
                                               | (Direct Socket or REST API)
                                               v
                     +----------------------------------------------------+
                     |                  Docker Environment                |
                     |  +----------------------------------------------+  |
                     |  |               Shared Volume                  |  |
                     |  |              /tmp/cape-external              |  |
                     |  +----------------------------------------------+  |
                     |         ^                  ^                  ^    |
                     |         | (Volume Mount)   | (Volume Mount)   |    |
                     |         v                  v                  v    |
                     |  +--------------+  +--------------+  +-----------+ |
                     |  |  Container   |  |  Container   |  | Container | |
                     |  |  cape-7z     |  |cape-innoext..|  | cape-upx  | |
                     |  | Network:None |  | Network:None |  |Network:None |
                     |  +--------------+  +--------------+  +-----------+ |
                     +----------------------------------------------------+

The system operates in one of two modes:

1. **Mounted Mode (Local Exec - Recommended):** CAPE writes files to a shared volume and invokes execution via the Docker socket (``docker-py`` SDK or ``sudo docker exec``).
2. **API Mode (Centralized Extraction Server):** Useful for multi-node deployments. CAPE communicates over HTTP with a central FastAPI Gateway that mounts the volume and orchestrates the containers.

---------------------------------------------------------
Dynamic Custom Modules Support (file_extra_info_modules/)
---------------------------------------------------------

CAPEv2 supports loading custom extraction modules dynamically from the ``lib/cuckoo/common/integrations/file_extra_info_modules/`` directory (e.g., ``msi_extract.py``).

To make this architecture fully extensible and seamless:

*   **Pure-Python logic** (such as seeking byte offsets in ``overlay.py`` or reading zip files in ``pyinstaller.py``) runs natively on the host because it is secure and does not execute compiled binaries.
*   **Compiled binary invocations** are intercepted at the central ``run_tool`` function. Any custom module that calls ``run_tool`` (such as ``msi_extract.py`` calling ``msiextract`` or ``7z``) **automatically inherits full Docker containerization and network isolation with zero code changes**.

---------------------------
Prerequisites & Installation
---------------------------

1. Install Docker & Docker Compose
==================================

Ensure Docker and the Docker Compose plugin are installed on your host:

.. code-block:: bash

    # Verify installations
    $ docker --version
    $ docker compose version

2. Install CAPEv2 Optional Docker Dependencies
==============================================

Install the Python Docker SDK (``docker-py``) under CAPEv2's optional dependencies:

.. code-block:: bash

    $ pip install .[docker]
    # or if using uv
    $ uv pip install -e .[docker]

-----------------------------------------
Deployment Configuration (docker-compose.yml)
-----------------------------------------

Save the following file to ``extra/docker/docker-compose.yml``. This configuration automatically links local compilation contexts with image tags, forces **strict offline networking**, and configures automatic startup on system boot.

.. code-block:: yaml

    version: '3.8'

    services:
      # Optional: The central REST API Gateway (only required if deploying in 'api' mode)
      api-gateway:
        image: capesandbox/cape-api-gateway:latest
        container_name: cape-api-gateway
        restart: unless-stopped
        ports:
          - "8000:8000"
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock
          - /tmp/cape-external:/tmp/cape-external
        environment:
          - MODE=api

      # ----------------- Tool-Specific Containers -----------------

      cape-innoextract:
        # Pulls official if available, otherwise tags local custom build
        image: capesandbox/cape-innoextract:latest
        build:
          context: ./innoextract
          dockerfile: Dockerfile
        container_name: cape-innoextract
        restart: unless-stopped
        # STOPS INTERNET ROUTING: Completely disables the container's network stack
        network_mode: "none"
        volumes:
          - /tmp/cape-external:/tmp/cape-external
        entrypoint: ["sleep", "infinity"]

      cape-7z:
        image: capesandbox/cape-7z:latest
        build:
          context: ./7z
          dockerfile: Dockerfile
        container_name: cape-7z
        restart: unless-stopped
        # STOPS INTERNET ROUTING: Completely disables the container's network stack
        network_mode: "none"
        volumes:
          - /tmp/cape-external:/tmp/cape-external
        entrypoint: ["sleep", "infinity"]

--------------------------------------------
Hardening & Security (Sudoers Restriction)
--------------------------------------------

Adding the ``cape`` user to the ``docker`` group grants **unrestricted root privileges** over the host (allowing privilege escalation via arbitrary volume binds).

To secure production environments, **do not** add the ``cape`` user to the ``docker`` group. Instead, use a restricted ``/etc/sudoers`` policy to let ``cape`` execute specific commands on specific containers.

1. Configure /etc/sudoers
=========================

Add the following lines to ``/etc/sudoers`` (use ``sudo visudo`` to edit safely):

.. code-block:: sudoers

    # Allow cape user to run exec on specific container tools without password prompts
    cape ALL=(ALL) NOPASSWD: /usr/bin/docker exec cape-innoextract *, /usr/bin/docker exec cape-7z *, /usr/bin/docker exec cape-upx *

2. Enable in CAPEv2 Configuration
=================================

Enable ``sudo_restriction`` inside your configuration (``processing.conf``):

.. code-block:: ini

    [docker_extra_info]
    enabled = yes
    mode = mounted
    sudo_restriction = yes
    shared_volume_path = /tmp/cape-external

When ``sudo_restriction`` is enabled, CAPEv2 bypasses the Python Docker SDK (which requires raw ``/var/run/docker.sock`` R/W access) and executes commands via the secure ``sudo`` command line:

.. code-block:: bash

    $ sudo docker exec -w /tmp/cape-external cape-innoextract innoextract <file>

----------------------------
Hybrid Host/Docker Execution Mode
----------------------------

CAPEv2 supports a hybrid configuration where some tools are executed inside Docker containers while others are executed directly on the host machine. This is useful for migrating incrementally or avoiding containerization latency on extremely simple/safe tools.

To configure a specific tool to run on the host even if ``docker_extra_info`` is globally enabled, add ``run_in_docker = no`` under that specific tool's section in ``integrations.conf`` or ``processing.conf``:

.. code-block:: ini

    # In integrations.conf:
    [SevenZip_unpack]
    enabled = yes
    run_in_docker = no  # This tool will run directly on the host

    # In processing.conf:
    [trid]
    enabled = yes
    run_in_docker = no  # This tool will run directly on the host

--------------------
Operating Guidelines
--------------------

How to Build Custom Images Locally
==================================

If you need to patch an extractor or customize a dependency (e.g., adding local scripts or updating a compiler inside a container):

1. Edit the tool's local Dockerfile under ``extra/docker/<tool>/Dockerfile``.
2. Recompile the image locally:

   .. code-block:: bash

       $ cd extra/docker/
       $ docker compose build cape-innoextract

3. Restart the container:

   .. code-block:: bash

       $ docker compose up -d cape-innoextract

How to Startup on Boot
======================

Since the services are configured with ``restart: unless-stopped``, they will **automatically start on system boot** as soon as the Docker systemd daemon launches.

To enable Docker at boot on your host:

.. code-block:: bash

    $ sudo systemctl enable docker

-----------------------------
Verification & Troubleshooting
-----------------------------

1. Verify Containers are Running
================================

.. code-block:: bash

    $ docker ps

All parser containers (``cape-innoextract``, ``cape-7z``, etc.) should show status ``Up`` with command ``sleep infinity``.

2. Verify Strict Offline Isolation
==================================

Run a test ping inside one of the tool containers. It must fail immediately with a "Network is unreachable" error:

.. code-block:: bash

    $ docker exec cape-innoextract ping -c 1 8.8.8.8
    # Expected output:
    # ping: sendto: Network is unreachable

3. Verify Dynamic Module Containerization
=========================================

Add a custom module under ``file_extra_info_modules/`` that uses ``run_tool``. Trigger static analysis on a sample, and verify in Docker logs that the container executed the tool:

.. code-block:: bash

    $ docker logs cape-innoextract

4. Check CAPEv2 Integration Fallback
====================================

If Docker is misconfigured, CAPEv2 automatically falls back to native host binaries (if installed) or prints detailed logs into the processing pipeline:

.. code-block:: bash

    $ tail -f /opt/CAPEv2/log/cuckoo.log | grep file_extra_info
