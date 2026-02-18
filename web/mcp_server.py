import json
import os
import sys
import mimetypes
import re
from typing import Any, Dict

# Ensure CAPE root is in path for lib imports
CAPE_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CAPE_ROOT)

try:
    import httpx
    from fastmcp import FastMCP
except ImportError:
    sys.exit("poetry run pip install .[mcp]")

try:
    from lib.cuckoo.common.config import Config
except ImportError:
    sys.exit("Could not import lib.cuckoo.common.config. Ensure you are running from CAPE root.")

# Initialize CAPE Config
api_config = Config("api")

# Configuration from Environment or Config File
# Run with: CAPE_API_URL=http://127.0.0.1:8000/apiv2 CAPE_API_TOKEN=your_token python3 web/mcp_server.py
API_URL = os.environ.get("CAPE_API_URL")
if not API_URL:
    # Try to get from api.conf [api] url
    try:
        base_url = api_config.api.url.rstrip("/")
        API_URL = f"{base_url}/apiv2"
    except AttributeError:
        API_URL = "http://127.0.0.1:8000/apiv2"

API_TOKEN = os.environ.get("CAPE_API_TOKEN", "")

# Proactively map enabled MCP tools. Default is NO.
ENABLED_MCP_TOOLS = set()
for section_name in api_config.get_config():
    if section_name == "api":
        continue
    try:
        section = api_config.get(section_name)
        if getattr(section, "mcp", False):
            ENABLED_MCP_TOOLS.add(section_name)
    except Exception:
        continue

def check_mcp_enabled(section: str) -> bool:
    """Check if a specific section is enabled for MCP."""
    return section in ENABLED_MCP_TOOLS

def mcp_tool(section: str):
    """
    Conditional decorator that only registers the tool with FastMCP
    if the corresponding section is enabled in api.conf.
    """
    def decorator(func):
        if check_mcp_enabled(section):
            return mcp.tool()(func)
        return func
    return decorator

def is_auth_required() -> bool:
    """Check if token authorization is enabled globally."""
    try:
        return api_config.api.token_auth_enabled
    except AttributeError:
        return False

# Initialize FastMCP
mcp = FastMCP("cape-sandbox")

# Security: Restrict file submission to a specific directory
# Defaults to current working directory if not set
ALLOWED_SUBMISSION_DIR = os.environ.get("CAPE_ALLOWED_SUBMISSION_DIR", os.getcwd())

def get_headers(token: str = "") -> Dict[str, str]:
    headers = {}
    auth_token = token if token else API_TOKEN

    if auth_token:
        headers["Authorization"] = f"Token {auth_token}"
    return headers

async def _request(method: str, endpoint: str, token: str = "", **kwargs) -> Any:
    # Auth Check
    if is_auth_required():
        auth_token = token if token else API_TOKEN
        if not auth_token:
             return {"error": True, "message": "Authentication required but no token provided."}

    url = f"{API_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(method, url, headers=get_headers(token), **kwargs)
            # We don't raise_for_status immediately to handle API errors gracefully in JSON
            if response.status_code >= 400:
                 try:
                    return response.json()
                 except json.JSONDecodeError:
                    return {"error": True, "message": f"HTTP {response.status_code}", "body": response.text}

            try:
                return response.json()
            except json.JSONDecodeError:
                return {"error": False, "data": response.text}
        except httpx.HTTPStatusError as e:
            return {"error": True, "message": str(e), "body": e.response.text}
        except Exception as e:
            return {"error": True, "message": str(e)}

async def _download_file(endpoint: str, destination: str, default_filename: str = "downloaded_file.bin", token: str = "") -> str:
    """Helper to download a file from an API endpoint."""
    # Auth Check
    if is_auth_required():
        auth_token = token if token else API_TOKEN
        if not auth_token:
             return json.dumps({"error": True, "message": "Authentication required but no token provided."}, indent=2)

    if not os.path.isdir(destination):
         return json.dumps({"error": True, "message": "Destination directory does not exist"})

    url = f"{API_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    headers = get_headers(token)

    async with httpx.AsyncClient() as client:
        try:
            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code != 200:
                    content = await response.read()
                    return json.dumps({"error": True, "message": f"HTTP {response.status_code}", "body": content.decode('utf-8', errors='ignore')}, indent=2)

                filename = default_filename
                content_disposition = response.headers.get("content-disposition")
                if content_disposition:
                    match = re.search(r'filename="?([^"]+)"?', content_disposition)
                    if match:
                        filename = os.path.basename(match.group(1))

                filepath = os.path.join(destination, filename)

                with open(filepath, "wb") as f:
                    async for chunk in response.aiter_bytes():
                        f.write(chunk)

                return json.dumps({"error": False, "message": f"Saved to {filepath}", "path": filepath}, indent=2)
        except Exception as e:
            return json.dumps({"error": True, "message": str(e)}, indent=2)

def _build_submission_data(**kwargs) -> Dict[str, str]:
    """Helper to build submission data dictionary, handling type conversions."""
    data = {}
    for key, value in kwargs.items():
        # Skip empty values (None, "", 0, False) to match original behavior
        if not value:
            continue

        if isinstance(value, bool):
            data[key] = "1"
        elif isinstance(value, int):
            data[key] = str(value)
        else:
            data[key] = value
    return data

# --- Tasks Creation ---

@mcp_tool("filecreate")
async def submit_file(
    file_path: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    timeout: int = 0,
    platform: str = "",
    memory: bool = False,
    enforce_timeout: bool = False,
    clock: str = "",
    custom: str = "",
    token: str = ""
) -> str:
    """
    Submit a local file for analysis.
    """
    # Auth Check (Manual check needed here because we stream file)
    if is_auth_required():
        auth_token = token if token else API_TOKEN
        if not auth_token:
             return json.dumps({"error": True, "message": "Authentication required but no token provided."})

    if not os.path.exists(file_path):
        return json.dumps({"error": True, "message": "File not found"})

    # Security check: Ensure file is within allowed directory
    abs_file_path = os.path.abspath(file_path)
    abs_allowed_dir = os.path.abspath(ALLOWED_SUBMISSION_DIR)

    if not abs_file_path.startswith(abs_allowed_dir):
        return json.dumps({
            "error": True,
            "message": f"Security Violation: File submission is restricted to {abs_allowed_dir}"
        })

    filename = os.path.basename(file_path)
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    data = _build_submission_data(
        machine=machine, package=package, options=options, tags=tags,
        priority=priority, timeout=timeout, platform=platform,
        memory=memory, enforce_timeout=enforce_timeout, clock=clock,
        custom=custom
    )

    url = f"{API_URL.rstrip('/')}/tasks/create/file/"

    async with httpx.AsyncClient() as client:
        try:
            with open(file_path, "rb") as f:
                files = {"file": (filename, f, mime_type)}
                response = await client.post(url, data=data, files=files, headers=get_headers(token))
                try:
                    result = response.json()
                except json.JSONDecodeError:
                    result = {"error": response.status_code >= 400, "data": response.text}
        except Exception as e:
            result = {"error": True, "message": str(e)}

    return json.dumps(result, indent=2)

@mcp_tool("urlcreate")
async def submit_url(
    url: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    timeout: int = 0,
    platform: str = "",
    memory: bool = False,
    enforce_timeout: bool = False,
    clock: str = "",
    custom: str = "",
    token: str = ""
) -> str:
    """Submit a URL for analysis."""
    data = {"url": url}
    data.update(_build_submission_data(
        machine=machine, package=package, options=options, tags=tags,
        priority=priority, timeout=timeout, platform=platform,
        memory=memory, enforce_timeout=enforce_timeout, clock=clock,
        custom=custom
    ))

    result = await _request("POST", "tasks/create/url/", token=token, data=data)
    return json.dumps(result, indent=2)

@mcp_tool("dlnexeccreate")
async def submit_dlnexec(
    url: str,
    machine: str = "",
    package: str = "",
    options: str = "",
    tags: str = "",
    priority: int = 1,
    token: str = ""
) -> str:
    """Submit a URL for Download & Execute analysis."""
    data = {"dlnexec": url}
    data.update(_build_submission_data(
        machine=machine, package=package, options=options, tags=tags, priority=priority
    ))

    result = await _request("POST", "tasks/create/dlnexec/", token=token, data=data)
    return json.dumps(result, indent=2)

@mcp_tool("staticextraction")
async def submit_static(
    file_path: str,
    priority: int = 1,
    options: str = "",
    token: str = ""
) -> str:
    """Submit a file for static extraction only."""
    # Auth Check (Manual check needed here because we stream file)
    if is_auth_required():
        auth_token = token if token else API_TOKEN
        if not auth_token:
             return json.dumps({"error": True, "message": "Authentication required but no token provided."})

    if not os.path.exists(file_path):
        return json.dumps({"error": True, "message": "File not found"})

    # Security check: Ensure file is within allowed directory
    abs_file_path = os.path.abspath(file_path)
    abs_allowed_dir = os.path.abspath(ALLOWED_SUBMISSION_DIR)

    if not abs_file_path.startswith(abs_allowed_dir):
        return json.dumps({
            "error": True,
            "message": f"Security Violation: File submission is restricted to {abs_allowed_dir}"
        })

    filename = os.path.basename(file_path)
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    data = _build_submission_data(priority=priority, options=options)

    url = f"{API_URL.rstrip('/')}/tasks/create/static/"

    async with httpx.AsyncClient() as client:
        try:
            with open(file_path, "rb") as f:
                files = {"file": (filename, f, mime_type)}
                response = await client.post(url, data=data, files=files, headers=get_headers(token))
                try:
                    result = response.json()
                except json.JSONDecodeError:
                    result = {"error": response.status_code >= 400, "data": response.text}
        except Exception as e:
            result = {"error": True, "message": str(e)}

    return json.dumps(result, indent=2)

# --- Task Management & Search ---

@mcp_tool("tasksearch")
async def search_task(hash_value: str, token: str = "") -> str:
    """Search for tasks by MD5, SHA1, or SHA256."""
    algo = "md5"
    if len(hash_value) == 40:
        algo = "sha1"
    elif len(hash_value) == 64:
        algo = "sha256"

    result = await _request("GET", f"tasks/search/{algo}/{hash_value}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("extendedtasksearch")
async def extended_search(option: str, argument: str, token: str = "") -> str:
    """
    Search tasks using extended options.
    Options include: id, name, type, string, ssdeep, crc32, file, command, resolvedapi, key, mutex, domain, ip, signature, signame, etc.
    """
    data = {"option": option, "argument": argument}
    result = await _request("POST", "tasks/extendedsearch/", token=token, data=data)
    return json.dumps(result, indent=2)

@mcp_tool("tasklist")
async def list_tasks(limit: int = 10, offset: int = 0, status: str = "", token: str = "") -> str:
    """List tasks with optional limit, offset and status filter."""
    params = {}
    if status:
        params["status"] = status

    endpoint = f"tasks/list/{limit}/{offset}/"
    result = await _request("GET", endpoint, token=token, params=params)
    return json.dumps(result, indent=2)

@mcp_tool("taskview")
async def view_task(task_id: int, token: str = "") -> str:
    """Get details of a specific task."""
    result = await _request("GET", f"tasks/view/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskresched")
async def reschedule_task(task_id: int, token: str = "") -> str:
    """Reschedule a task."""
    result = await _request("GET", f"tasks/reschedule/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskreprocess")
async def reprocess_task(task_id: int, token: str = "") -> str:
    """Reprocess a task."""
    result = await _request("GET", f"tasks/reprocess/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskstatus")
async def get_task_status(task_id: int, token: str = "") -> str:
    """Get the status of a task."""
    result = await _request("GET", f"tasks/status/{task_id}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("tasks_latest")
async def get_latest_tasks(hours: int = 24, token: str = "") -> str:
    """Get IDs of tasks finished in the last X hours."""
    result = await _request("GET", f"tasks/get/latests/{hours}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("statistics")
async def get_statistics(days: int = 7, token: str = "") -> str:
    """Get task statistics for the last X days."""
    result = await _request("GET", f"tasks/statistics/{days}/", token=token)
    return json.dumps(result, indent=2)

# --- Reports & IOCs ---

@mcp_tool("taskreport")
async def get_task_report(task_id: int, format: str = "json", token: str = "") -> str:
    """Get the analysis report for a task (json, lite, maec, metadata)."""
    result = await _request("GET", f"tasks/get/report/{task_id}/{format}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("taskiocs")
async def get_task_iocs(task_id: int, detailed: bool = False, token: str = "") -> str:
    """Get IOCs for a task."""
    endpoint = f"tasks/get/iocs/{task_id}/"
    if detailed:
        endpoint += "detailed/"
    result = await _request("GET", endpoint, token=token)
    return json.dumps(result, indent=2)

@mcp_tool("capeconfig")
async def get_task_config(task_id: int, token: str = "") -> str:
    """Get the extracted malware configuration for a task."""
    result = await _request("GET", f"tasks/get/config/{task_id}/", token=token)
    return json.dumps(result, indent=2)

# --- File Downloads ---

@mcp_tool("taskscreenshot")
async def download_task_screenshot(task_id: int, destination: str, screenshot_id: str = "all", token: str = "") -> str:
    """Download task screenshots (zip or single image)."""
    return await _download_file(f"tasks/get/screenshot/{task_id}/{screenshot_id}/", destination, f"{task_id}_screenshots.zip", token=token)

@mcp_tool("taskpcap")
async def download_task_pcap(task_id: int, destination: str, token: str = "") -> str:
    """Download the PCAP file for a task."""
    return await _download_file(f"tasks/get/pcap/{task_id}/", destination, f"{task_id}_dump.pcap", token=token)

@mcp_tool("tasktlspcap")
async def download_task_tlspcap(task_id: int, destination: str, token: str = "") -> str:
    """Download the TLS PCAP file for a task."""
    return await _download_file(f"tasks/get/tlspcap/{task_id}/", destination, f"{task_id}_tls.pcap", token=token)

@mcp_tool("taskevtx")
async def download_task_evtx(task_id: int, destination: str, token: str = "") -> str:
    """Download the EVTX logs for a task."""
    return await _download_file(f"tasks/get/evtx/{task_id}/", destination, f"{task_id}_evtx.zip", token=token)

@mcp_tool("taskdropped")
async def download_task_dropped(task_id: int, destination: str, token: str = "") -> str:
    """Download dropped files for a task."""
    return await _download_file(f"tasks/get/dropped/{task_id}/", destination, f"{task_id}_dropped.zip", token=token)

@mcp_tool("taskselfextracted")
async def download_self_extracted_files(task_id: int, destination: str, tool: str = "all", token: str = "") -> str:
    """Download self-extracted files for a task."""
    return await _download_file(f"tasks/get/selfextracted/{task_id}/{tool}/", destination, f"{task_id}_selfextracted_{tool}.zip", token=token)

@mcp_tool("tasksurifile")
async def download_task_surifile(task_id: int, destination: str, token: str = "") -> str:
    """Download Suricata files for a task."""
    return await _download_file(f"tasks/get/surifile/{task_id}/", destination, f"{task_id}_surifiles.zip", token=token)

@mcp_tool("taskmitmdump")
async def download_task_mitmdump(task_id: int, destination: str, token: str = "") -> str:
    """Download mitmdump HAR file for a task."""
    return await _download_file(f"tasks/get/mitmdump/{task_id}/", destination, f"{task_id}_dump.har", token=token)

@mcp_tool("payloadfiles")
async def download_task_payloadfiles(task_id: int, destination: str, token: str = "") -> str:
    """Download CAPE payload files."""
    return await _download_file(f"tasks/get/payloadfiles/{task_id}/", destination, f"{task_id}_payloads.zip", token=token)

@mcp_tool("procdumpfiles")
async def download_task_procdumpfiles(task_id: int, destination: str, token: str = "") -> str:
    """Download CAPE procdump files."""
    return await _download_file(f"tasks/get/procdumpfiles/{task_id}/", destination, f"{task_id}_procdumps.zip", token=token)

@mcp_tool("taskprocmemory")
async def download_task_procmemory(task_id: int, destination: str, pid: str = "all", token: str = "") -> str:
    """Download process memory dumps."""
    return await _download_file(f"tasks/get/procmemory/{task_id}/{pid}/", destination, f"{task_id}_procmemory.zip", token=token)

@mcp_tool("taskfullmemory")
async def download_task_fullmemory(task_id: int, destination: str, token: str = "") -> str:
    """Download full VM memory dump."""
    return await _download_file(f"tasks/get/fullmemory/{task_id}/", destination, f"{task_id}_fullmemory.dmp", token=token)

# --- Files & Machines ---

@mcp_tool("fileview")
async def view_file(hash_value: str, hash_type: str = "sha256", token: str = "") -> str:
    """View information about a file in the database."""
    return await _request("GET", f"files/view/{hash_type}/{hash_value}/", token=token)

@mcp_tool("sampledl")
async def download_sample(hash_value: str, destination: str, hash_type: str = "sha256", token: str = "") -> str:
    """Download a sample from the database."""
    return await _download_file(f"files/get/{hash_type}/{hash_value}/", destination, f"{hash_value}.bin", token=token)

@mcp_tool("machinelist")
async def list_machines(token: str = "") -> str:
    """List available analysis machines."""
    result = await _request("GET", "machines/list/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("machineview")
async def view_machine(name: str, token: str = "") -> str:
    """View details of a specific machine."""
    result = await _request("GET", f"machines/view/{name}/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("list_exitnodes")
async def list_exitnodes(token: str = "") -> str:
    """List available exit nodes."""
    result = await _request("GET", "exitnodes/", token=token)
    return json.dumps(result, indent=2)

@mcp_tool("cuckoostatus")
async def get_cuckoo_status(token: str = "") -> str:
    """Get the status of the CAPE host."""
    result = await _request("GET", "cuckoo/status/", token=token)
    return json.dumps(result, indent=2)

if __name__ == "__main__":
    mcp.run()
