# Go Fast-Fetcher for CAPE Distributed

This utility replaces the Python-based report retrieval in `dist.py` with a high-performance Go binary. It supports NFS-based report retrieval, copying analysis results directly from mounted worker storage to the master storage.

## Features
- **High Concurrency:** Retrieves reports from multiple worker nodes simultaneously.
- **NFS Support:** Copies reports directly from NFS mounts (replacing HTTP downloads).
- **Auto-Cleanup:** Deletes tasks from worker nodes after successful retrieval.
- **Configurable:** Uses a JSON config file for database and path settings.

## Build
```bash
go mod tidy
go build -o go-fetcher
```

## Configuration
Create a `config.json` file:

```json
{
    "DistDBConn": "postgresql://cape:cape@127.0.0.1:5432/distdb",
    "MainDBConn": "postgresql://cape:cape@127.0.0.1:5432/cape",
    "RootDir": "/opt/CAPEv2",
    "Threads": 8,
    "IgnorePatterns": [
        "binary",
        "dump_sorted.pcap",
        "memory.dmp",
        "logs",
        "custom_folder"
    ],
    "NFSMountFolder": "/opt/CAPEv2/workers"
}
```

* `NFSMountFolder`: The base path where worker nodes are mounted (e.g., `/mnt/cape_workers/node1/...`).

## Usage

1. **Stop existing retrieval:**
   Run `dist.py` with the `--submit-only` flag to disable its internal fetcher.
   ```bash
   poetry run python utils/dist.py --submit-only
   ```

2. **Run the Go Fetcher:**
   ```bash
   ./go-fetcher -config config.json
   ```

## CLI Arguments
CLI flags override config file settings:
- `-config`: Path to JSON config file.
- `-nfs-mount`: Base path for NFS mounts.
- `-root`: CAPE root directory.
- `-threads`: Number of worker threads.
