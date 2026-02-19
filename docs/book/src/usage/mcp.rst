CAPE Sandbox MCP Server
=======================

This MCP (Model Context Protocol) server allows AI agents (like Antigravity, Gemini, Claude Desktop, Cursor, etc.) to interact directly with your CAPE Sandbox instance.

Features
--------

Exposes the following tools to AI agents:

**Task Submission:**

*   ``submit_file``: Submit a local file for sandbox analysis.
*   ``submit_url``: Submit a URL for sandbox analysis.
*   ``submit_dlnexec``: Submit a URL for "Download & Execute" analysis.
*   ``submit_static``: Submit a file for static extraction only.

**Task Management & Search:**

*   ``search_task``: Find previous analyses by MD5/SHA1/SHA256 hashes.
*   ``extended_search``: Advanced search by various criteria (filename, type, ssdeep, etc.).
*   ``list_tasks``: List recent tasks with optional status filtering.
*   ``view_task``: Get detailed information about a specific task.
*   ``get_task_status``: Check if an analysis is pending, running, or completed.
*   ``reschedule_task``: Reschedule a task to run again.
*   ``reprocess_task``: Reprocess a task's existing data.
*   ``delete_task``: Delete a task from the database.

**Reports & Intelligence:**

*   ``get_task_report``: Retrieve analysis reports (json, maec, etc.).
*   ``get_task_iocs``: Retrieve Indicators of Compromise (IOCs).
*   ``get_task_config``: Retrieve extracted malware configuration.
*   ``get_statistics``: Get global task statistics.
*   ``get_latest_tasks``: Get IDs of recently finished tasks.

**Downloads:**

*   ``download_task_screenshot``: Download analysis screenshots.
*   ``download_task_pcap``: Download network traffic capture (PCAP).
*   ``download_task_tlspcap``: Download TLS-decrypted network traffic.
*   ``download_task_dropped``: Download files dropped during analysis.
*   ``download_self_extracted_files``: Download files extracted by CAPE (e.g. unpacked payloads).
*   ``download_task_payloadfiles``: Download CAPE payload files.
*   ``download_task_procdumpfiles``: Download process dumps.
*   ``download_task_procmemory``: Download process memory dumps.
*   ``download_task_fullmemory``: Download full VM memory dump.
*   ``download_task_evtx``: Download Windows Event Logs (EVTX).
*   ``download_task_surifile``: Download Suricata captured files.
*   ``download_task_mitmdump``: Download mitmdump HAR file.

**Infrastructure & Files:**

*   ``list_machines``: See available analysis VMs.
*   ``view_machine``: Get details about a specific VM.
*   ``list_exitnodes``: List available network exit nodes.
*   ``view_file``: Get information about a file in the database.
*   ``download_sample``: Download a malware sample from the database.
*   ``get_cuckoo_status``: Get the health/status of the CAPE host.

Installation
------------

You can install the required dependencies using the ``mcp`` extra:

.. code-block:: bash

    poetry run pip install .[mcp]

Configuration
-------------

The MCP server integrates with CAPE's standard configuration system and environment variables.

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

*   ``CAPE_API_URL``: (Optional) The full path to your CAPE API v2 endpoint (e.g., ``http://127.0.0.1:8000/apiv2``). If not set, it defaults to the ``url`` in ``api.conf`` + ``/apiv2``.
*   ``CAPE_API_TOKEN``: (Optional) Your API token. Recommended to set this in the **Client Configuration** (e.g. ``claude_desktop_config.json``) rather than your system's global environment variables to ensure isolation.
*   ``CAPE_ALLOWED_SUBMISSION_DIR``: (Optional) Restricts ``submit_file`` to a specific local directory for security. Defaults to the current working directory.

Granular Tool Control (``api.conf``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can enable or disable specific tools for the MCP server by modifying ``conf/api.conf``. Each API section now supports an ``mcp`` toggle:

.. code-block:: ini

    [filecreate]
    enabled = yes
    mcp = yes    # Set to 'no' to hide this tool from the AI agent

    [taskdelete]
    enabled = no
    mcp = no     # AI will not see 'delete_task'

**Note:** Tools disabled via ``mcp = no`` are not even registered with the MCP server; the AI agent will not see them in its available toolset.

Authentication & Security Architecture
--------------------------------------

Proper security depends on how you deploy the MCP server.

Scenario A: Local / Stdio (Recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this mode, the AI Client (Claude, Gemini, etc.) spawns a private instance of the MCP server process for your session. This is the most secure method.

1.  **Configuration:** Add your ``CAPE_API_TOKEN`` to the **Client's Configuration file** (e.g., ``claude_desktop_config.json``), **not** your system's global environment variables.
2.  **Isolation:** Because the process is spawned by your client, the token is isolated to your session. Other users on the machine cannot see or use your token.
3.  **Usage:** You do **not** need to provide a token in your prompts. The server automatically uses the environment variable provided by the client.

Scenario B: Remote / Shared Server (SSE)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this mode, a single MCP server instance runs continuously and accepts connections from multiple clients over the network.

1.  **Configuration:** Start the server **without** a ``CAPE_API_TOKEN`` environment variable.
2.  **Strict Mode:** Ensure ``token_auth_enabled = yes`` is set in ``conf/api.conf``.
3.  **Usage:** Users **must** provide their API token in the ``token`` argument for every tool call (e.g., ``submit_file(..., token="MyKey")``).
4.  **Risk:** Do not set a global token in this mode, or all users will inherit those privileges.

Authentication Priority
~~~~~~~~~~~~~~~~~~~~~~~

The server determines which token to use in this specific order:

1.  **Per-Request Token:** Argument passed to the specific tool (e.g., ``token="xyz"``).
2.  **Environment Token:** ``CAPE_API_TOKEN`` variable (set in Client Config for Stdio).

If ``token_auth_enabled = yes`` and no token is found in either location, the request is rejected.

Running the Server
------------------

Standard execution
~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    CAPE_API_URL=http://your-cape-ip:8000/apiv2 CAPE_API_TOKEN=your_token python3 web/mcp_server.py

Client Integrations
-------------------

The CAPE MCP server can be used with any MCP-compliant client. Here are examples for popular clients.

Claude Desktop
~~~~~~~~~~~~~~

Add the following to your ``claude_desktop_config.json``:

.. code-block:: json

    {
      "mcpServers": {
        "cape": {
          "command": "poetry",
          "args": ["run", "python", "/opt/CAPEv2/web/mcp_server.py"],
          "env": {
            "CAPE_API_URL": "http://127.0.0.1:8000/apiv2",
            "CAPE_API_TOKEN": "YOUR_API_TOKEN_HERE",
            "CAPE_ALLOWED_SUBMISSION_DIR": "/home/user/samples"
          }
        }
      }
    }

Gemini CLI
~~~~~~~~~~

You can add the server using the CLI command:

.. code-block:: bash

    gemini mcp add cape poetry run python /opt/CAPEv2/web/mcp_server.py \
      -e CAPE_API_URL=http://127.0.0.1:8000/apiv2 \
      -e CAPE_API_TOKEN=YOUR_API_TOKEN_HERE \
      -e CAPE_ALLOWED_SUBMISSION_DIR=/home/user/samples

Or manually add it to your ``~/.gemini/settings.json``:

.. code-block:: json

    {
      "mcpServers": {
        "cape": {
          "command": "poetry",
          "args": ["run", "python", "/opt/CAPEv2/web/mcp_server.py"],
          "env": {
            "CAPE_API_URL": "http://127.0.0.1:8000/apiv2",
            "CAPE_API_TOKEN": "YOUR_API_TOKEN_HERE",
            "CAPE_ALLOWED_SUBMISSION_DIR": "/home/user/samples"
          }
        }
      }
    }

Antigravity
~~~~~~~~~~~

Open **Agent Panel** -> **...** -> **MCP Servers** -> **Manage MCP Servers** -> **View raw config** and add the following to ``mcp_config.json``:

.. code-block:: json

    {
      "mcpServers": {
        "cape": {
          "command": "poetry",
          "args": ["run", "python", "/opt/CAPEv2/web/mcp_server.py"],
          "env": {
            "CAPE_API_URL": "http://127.0.0.1:8000/apiv2",
            "CAPE_API_TOKEN": "YOUR_API_TOKEN_HERE",
            "CAPE_ALLOWED_SUBMISSION_DIR": "/home/user/samples"
          }
        }
      }
    }

Security Note
-------------

*   **Tool Filtering:** Use the ``mcp = no`` setting in ``api.conf`` to hide dangerous operations (like ``task_delete``) from the AI.
*   **Path Restriction:** Use ``CAPE_ALLOWED_SUBMISSION_DIR`` to ensure the AI cannot submit arbitrary sensitive files from your host system.
*   **Auth Enforcement:** Enable ``token_auth_enabled`` in ``api.conf`` to ensure all interactions are authenticated.
