### Do not use it yet!
* Once it will be ready this header will be removed and changelog.md will be updated!

# CAPE Agent (Go Port)

This is a Golang port of the CAPE Sandbox Agent. It is designed to be a drop-in replacement for the Python agent, offering better performance, zero dependencies (no Python installation required to *run* the agent), and improved stealth.

## Build Instructions

### Prerequisites
- Go 1.21 or higher

### Building for Windows (x86)
Most sandboxes use 32-bit Windows environments or require 32-bit compatibility.

```bash
GOOS=windows GOARCH=386 go build -ldflags="-s -w" -trimpath -o agent.exe
```

### Optimized & Small Binaries
To produce the smallest possible binary with no local path leaks:
- `-s`: Omit the symbol table and debug information.
- `-w`: Omit the DWARF symbol table.
- `-trimpath`: Remove all file system paths from the compiled executable.

#### (Optional) UPX Compression
If you need an extremely small binary (e.g., ~500KB), you can use UPX.
**Note:** UPX-packed binaries are often flagged by AV heuristics.
```bash
upx --best --lzma agent.exe
```

### Building for Windows (x64)

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o agent.exe
```

### Building for Linux

```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o agent
```

## Usage

In the VM, run the agent:

```cmd
agent.exe
or specify host and port. Default is 0.0.0.0:8000
agent.exe -host 0.0.0.0 -port 8000
```

## Features
- **Zero Dependency**: Runs as a standalone binary.
- **Stealth**: Can be renamed to anything (e.g., `svchost.exe`).
- **Compatibility**: Implements the full CAPE Agent API (v0.20).
- **Python Execution**: executing `.py` analysis scripts requires `python.exe` to be in the system `PATH`.

## Dev Notes
- **Mutexes**: Fully implemented using Windows syscalls.
- **ZipSlip Protection**: Built-in check against path traversal in zip extraction.

## How to pull file from VM to Host
### Start Agent with Auth (Optional but Recommended):

* `agent.exe -auth "my-secret-token-123"`

### Pull a file to HOST (CAPE):
```
# Host-side logic (e.g., in CAPE's auxiliary module)
requests.post(
    "http://<VM_IP>:8000/push",
    data={"filepath": "C:\\malware_output.txt", "port": "8000"},
    headers={"Authorization": "Bearer my-secret-token-123"}
)
# The agent will POST the file back to http://<HOST_IP>:8000/upload
```

## Agent update
* Consider update on start of the analysis if version mismatch

How it works (/update endpoint)
   1. Receive: The Host POSTs the new binary to the agent.
   2. Rename: The agent renames its own running executable to agent.exe.old.
   3. Save: It saves the new binary as agent.exe.
   4. Restart: It spawns the new agent.exe.
   5. Exit: The old agent process terminates, releasing port 8000.
       * Reliability: A retry loop has been added to the main() function. If the new agent starts before the old one has fully released port 8000, it will retry for 10 seconds instead of crashing.

Usage
  To update the agent on a running VM (from the Host):

```
import requests
# Upload the new agent binary
with open("agent_v2.exe", "rb") as f:
    requests.post(
        "http://<VM_IP>:8000/update",
        files={"file": f},
        headers={"Authorization": "Bearer <token>"} # If auth is enabled
    )
```
The agent will respond with 200 OK and then restart itself immediately.
