# CAPE Sandbox MCP Server

This MCP (Model Context Protocol) server allows AI agents (like Claude Desktop, Cursor, etc.) to interact directly with your CAPE Sandbox instance.

## Features

Exposes the following tools to AI agents:

**Task Submission:**
- `submit_file`: Submit a local file for sandbox analysis.
- `submit_url`: Submit a URL for sandbox analysis.
- `submit_dlnexec`: Submit a URL for "Download & Execute" analysis.
- `submit_static`: Submit a file for static extraction only.

**Task Management & Search:**
- `search_task`: Find previous analyses by MD5/SHA1/SHA256 hashes.
- `extended_search`: Advanced search by various criteria (filename, type, ssdeep, etc.).
- `list_tasks`: List recent tasks with optional status filtering.
- `view_task`: Get detailed information about a specific task.
- `get_task_status`: Check if an analysis is pending, running, or completed.
- `reschedule_task`: Reschedule a task to run again.
- `reprocess_task`: Reprocess a task's existing data.
- `delete_task`: Delete a task from the database.

**Reports & Intelligence:**
- `get_task_report`: Retrieve analysis reports (json, maec, etc.).
- `get_task_iocs`: Retrieve Indicators of Compromise (IOCs).
- `get_task_config`: Retrieve extracted malware configuration.
- `get_statistics`: Get global task statistics.
- `get_latest_tasks`: Get IDs of recently finished tasks.

**Downloads:**
- `download_task_screenshot`: Download analysis screenshots.
- `download_task_pcap`: Download network traffic capture (PCAP).
- `download_task_tlspcap`: Download TLS-decrypted network traffic.
- `download_task_dropped`: Download files dropped during analysis.
- `download_self_extracted_files`: Download files extracted by CAPE (e.g. unpacked payloads).
- `download_task_payloadfiles`: Download CAPE payload files.
- `download_task_procdumpfiles`: Download process dumps.
- `download_task_procmemory`: Download process memory dumps.
- `download_task_fullmemory`: Download full VM memory dump.
- `download_task_evtx`: Download Windows Event Logs (EVTX).
- `download_task_surifile`: Download Suricata captured files.
- `download_task_mitmdump`: Download mitmdump HAR file.

**Infrastructure & Files:**
- `list_machines`: See available analysis VMs.
- `view_machine`: Get details about a specific VM.
- `list_exitnodes`: List available network exit nodes.
- `view_file`: Get information about a file in the database.
- `download_sample`: Download a malware sample from the database.
- `get_cuckoo_status`: Get the health/status of the CAPE host.

## Installation

You can install the required dependencies using the `mcp` extra:

```bash
poetry run pip install .[mcp]
```

## Configuration

The server requires two environment variables:
- `CAPE_API_URL`: The full path to your CAPE API v2 endpoint (e.g., `http://127.0.0.1:8000/apiv2`).
- `CAPE_API_TOKEN`: Your CAPE API token (obtained from your user profile in the web UI).

## Running the Server

### Standard execution
```bash
CAPE_API_URL=http://your-cape-ip:8000/apiv2 CAPE_API_TOKEN=your_token python3 web/mcp_server.py
```

### Integration with Claude Desktop

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cape": {
      "command": "python3",
      "args": ["/path/to/CAPEv2/web/mcp_server.py"],
      "env": {
        "CAPE_API_URL": "http://127.0.0.1:8000/apiv2",
        "CAPE_API_TOKEN": "YOUR_API_TOKEN_HERE"
      }
    }
  }
}
```

## Security Note

This server exposes your sandbox capabilities to the AI. Ensure that you only enable this for agents you trust, as they will be able to submit files and read analysis results.
