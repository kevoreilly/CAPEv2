# CAPE Sandbox Developer Skills & Architecture Guide

This document outlines the architectural structure, core concepts, and development patterns for the CAPE Sandbox (v2). It serves as a guide for extending functionality, debugging, and maintaining the codebase.

## 1. Project Overview
CAPE (Config And Payload Extraction) is a malware analysis sandbox derived from Cuckoo Sandbox. It focuses on automated malware analysis with a specific emphasis on extracting payloads and configuration from malware.

**Core Tech Stack:**
- **Language:** Python 3
- **Web Framework:** Django
- **Database:** PostgreSQL (SQLAlchemy) for task management, MongoDB/Elasticsearch for results storage.
- **Virtualization:** KVM/QEMU (preferred), VirtualBox, VMWare.
- **Frontend:** HTML5, Bootstrap, Jinja2 Templates.

## 2. Directory Structure Key
| Directory | Purpose |
| :--- | :--- |
| `agent/` | Python script (`agent.py`) running *inside* the Guest VM to handle communication. |
| `analyzer/` | Core analysis components running *inside* the Guest VM (monitor, analyzers). |
| `conf/` | Configuration files (`cuckoo.conf`, `reporting.conf`, `web.conf`, etc.). |
| `data/` | Static assets, yara rules, monitor binaries, and HTML templates (`data/html`). |
| `lib/cuckoo/` | Core logic (Scheduler, Database, Guest Manager, Result Processor). |
| `modules/` | Pluggable components (Signatures, Processing, Reporting, Auxiliary). |
| `web/` | Django-based web interface (Views, URLs, Templates). |
| `utils/` | Standalone CLI utilities (`process.py`, `cleaners.py`, `rooter.py`). |

## 3. Core Workflows

### A. The Analysis Lifecycle
1.  **Submission:** User submits file/URL via WebUI (`web/submission/`) or API (`web/api/`).
2.  **Scheduling:** Task is added to SQL DB. `lib/cuckoo/core/scheduler.py` picks it up.
3.  **Execution:**
    *   VM is restored/started.
    *   `analyzer` is uploaded to VM.
    *   Sample is injected/executed.
    *   Behavior is monitored via API hooking (CAPE Monitor).
4.  **Result Collection:** Logs, PCAP, and dropped files are transferred back to Host.
5.  **Processing:** `modules/processing/` parses raw logs into a structured dictionary.
6.  **Signatures:** `modules/signatures/` runs logic against the processed data.
7.  **Reporting:** `modules/reporting/` exports data (JSON, HTML, MongoDB, MAEC).

### B. Web Interface Architecture
The Web UI is split into two distinct rendering logic paths:
1.  **Django Views (`web/analysis/views.py`):** Handles URL routing, authentication, and context generation. It fetches data from MongoDB/Elasticsearch.
2.  **Jinja2 Templates:**
    *   **Web Templates (`web/templates/`):** Standard Django templates for the UI.
    *   **Report Templates (`data/html/`):** Standalone Jinja2 templates used by the `reporthtml` module to generate static HTML reports. *Note: Changes here affect the downloadable HTML report, not necessarily the Web UI.*

## 4. Development Guides

### How to Add a Detection Signature
Signatures live in `modules/signatures/`.
```python
from lib.cuckoo.common.abstracts import Signature

class MyMalware(Signature):
    name = "my_malware_behavior"
    description = "Detects specific bad behavior"
    severity = 3
    categories = ["trojan"]
    authors = ["You"]

    def on_call(self, call, process):
        # Inspect individual API calls
        if call["api"] == "CreateFileW" and "evil.exe" in call["arguments"]["filepath"]:
            return True
```

### How to Add a Processing Module
Processing modules (`modules/processing/`) run after analysis to extract specific data (e.g., Static analysis of a file).
```python
from lib.cuckoo.common.abstracts import Processing

class MyExtractor(Processing):
    def run(self):
        self.key = "my_data" # Key in the final report JSON
        result = {}
        # ... logic ...
        return result
```

### How to Modify the Web Report
1.  **Locate the Template:** Look in `web/templates/analysis/`.
    *   `overview/index.html`: Main dashboard.
    *   `overview/_info.html`: General details.
    *   `overview/_summary.html`: Behavioral summary.
2.  **Edit:** Use Django template language (`{% if %}`, `{{ variable }}`).
3.  **Context:** Data is usually passed as `analysis` object. Access fields like `analysis.info.id`, `analysis.network`, `analysis.behavior`.

## 5. Troubleshooting & Debugging

### Common Issues
*   **"Waiting for container":** Usually a network configuration issue in `conf/cuckoo.conf` or `conf/auxiliary.conf`.
*   **Report Empty:** Check `reporting.conf`. If using MongoDB, ensure `mongodb` is enabled.
*   **Template Errors:** Use `{% if variable %}` guards aggressively. Missing keys in MongoDB documents cause Jinja2 crashes.

### Important Commands
*   `poetry run python cuckoo.py -d`: Run CAPE in debug mode (verbose logs).
*   `poetry run python utils/process.py -r <task_id>`: Re-run processing and reporting for a specific task without restarting the VM.
*   `poetry run python utils/cleaners.py --clean`: Wipe all tasks and reset the DB.

### Database Querying (MongoDB)
CAPE stores unstructured analysis results in the `analysis` collection.
```bash
mongo cuckoo
db.analysis.find({"info.id": 123}, {"behavior.summary": 1}).pretty()
```

## 6. Best Practices
1.  **Conditionally Render:** Always check if a dictionary key exists in templates before rendering to avoid UI breaks on different analysis types (Static vs Dynamic).
2.  **Keep Views Light:** Perform heavy data crunching in `modules/processing`, not in Django views.
3.  **Modular CSS/JS:** Keep custom styles in `web/static/` rather than inline in templates when possible.
