# CAPE Agent (Go Port)

This is a Golang port of the CAPE Sandbox Agent. It is designed to be a drop-in replacement for the Python agent, offering better performance, zero dependencies (no Python installation required to *run* the agent), and improved stealth.

## Build Instructions

### Prerequisites
- Go 1.21 or higher

### Building for Windows (x86)
Most sandboxes use 32-bit Windows environments or require 32-bit compatibility.

```bash
GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o agent.exe
```

### Building for Windows (x64)

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o agent.exe
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
