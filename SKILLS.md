---
name: cape-sandbox-developer
description: Comprehensive guide for architecture, development patterns, and advanced troubleshooting in CAPE Sandbox (v2).
---

# CAPE Sandbox Developer Skills & Architecture Guide

This document outlines the architectural structure, core concepts, and development patterns for the CAPE Sandbox (v2). It serves as a guide for extending functionality, debugging, and maintaining the codebase.

> **Agent Hint:** Use the referenced documentation files (`docs/book/src/...`) to dive deeper into specific topics.

## 1. Project Overview
CAPE (Config And Payload Extraction) is a malware analysis sandbox derived from Cuckoo Sandbox. It focuses on automated malware analysis with a specific emphasis on extracting payloads and configuration from malware.

*   **Ref:** `docs/book/src/introduction/what.rst`

**Core Tech Stack:**
- **Language:** Python 3
- **Web Framework:** Django
- **Database:** PostgreSQL (SQLAlchemy) for task management, MongoDB/Elasticsearch for results storage.
- **Virtualization:** KVM/QEMU (preferred), VirtualBox, VMWare, Azure, Google Cloud.
- **Frontend:** HTML5, Bootstrap, Jinja2 Templates.
- **Dependency Management:** Poetry.

## 2. Directory Structure Key
| Directory | Purpose |
| :--- | :--- |
| `agent/` | Python script (`agent.py`) running *inside* the Guest VM to handle communication. |
| `analyzer/` | Core analysis components running *inside* the Guest VM (monitor, analyzers, packages). |
| `conf/` | Default configuration files. **Do not edit directly**; use `custom/conf/`. |
| `custom/conf/` | User overrides for configuration files. |
| `data/` | Static assets, yara rules, monitor binaries, and HTML templates (`data/html`). |
| `lib/cuckoo/` | Core logic (Scheduler, Database, Guest Manager, Result Processor). |
| `modules/` | Pluggable components (Signatures, Processing, Reporting, Auxiliary, Machinery). |
| `web/` | Django-based web interface (Views, URLs, Templates). |
| `utils/` | Standalone CLI utilities (`process.py`, `submit.py`, `rooter.py`, `community.py`). |

## 3. Core Workflows

### A. The Analysis Lifecycle
1.  **Submission:** User submits file/URL via WebUI (`web/submission/`) or API (`web/api/`).
    *   **Ref:** `docs/book/src/usage/submit.rst`, `docs/book/src/usage/api.rst`
2.  **Scheduling:** Task is added to SQL DB. `lib/cuckoo/core/scheduler.py` picks it up.
3.  **Infrastructure:** 
    *   `modules/machinery` starts the VM.
    *   `utils/rooter.py` configures network routing (if applicable).
    *   **Ref:** `docs/book/src/usage/rooter.rst`
4.  **Execution:**
    *   VM is restored/started.
    *   `analyzer` is uploaded to VM.
    *   Sample is injected/executed using specific **Analysis Packages** (`analyzer/windows/modules/packages/`).
        *   **Ref:** `docs/book/src/usage/packages.rst`
    *   Behavior is monitored via API hooking (CAPE Monitor).
    *   **Auxiliary Modules** (`modules/auxiliary/`) run in parallel on the Host (e.g., Sniffer).
5.  **Result Collection:** Logs, PCAP, and dropped files are transferred back to Host.
6.  **Processing:** `modules/processing/` parses raw logs into a structured dictionary (Global Container).
7.  **Signatures:** `modules/signatures/` runs logic against the processed data.
8.  **Reporting:** `modules/reporting/` exports data (JSON, HTML, MongoDB, MAEC).

## 4. Configuration Management
*   **Overrides:** Never edit files in `conf/` directly. Create a copy in `custom/conf/` with the same name.
*   **Environment Variables:** You can use env vars in configs: `%(ENV:VARIABLE_NAME)s`.
*   **Conf.d:** You can create directories like `custom/conf/reporting.conf.d/` and add `.conf` files there for granular overrides.
*   **Ref:** `docs/book/src/installation/host/configuration.rst`

## 5. Development Guides
*   **Coding Style:** See `docs/book/src/development/code_style.rst`

### Coding Standards (PEP 8+)
*   **Imports:** Explicit imports only (`from lib import a, b`). No `from lib import *`. Group standard library, 3rd party, and local imports.
*   **Strings:** Use double quotes (`"`) for strings. (This line was corrected from the original prompt to reflect the actual change needed for the example.)
*   **Logging:** Use `import logging; log = logging.getLogger(__name__)`. Do not use `print()`.
*   **Exceptions:** Use custom exceptions from `lib/cuckoo/common/exceptions.py` (e.g., `CuckooOperationalError`).

### Local Development Environment

Dependencies are managed with **Poetry**; the test suite imports `sqlalchemy`,
`django` and friends, so a system Python without the project environment will
fail at collection time in `tests/conftest.py`.

```bash
poetry install
poetry run pytest tests/ -q
```

Use `poetry run <cmd>` (or activate the venv) for *every* Python invocation -
`pytest`, `ruff`, `black`, `alembic`, `python utils/...`.

**Linting.** `ruff` is the fast gate and is expected to be clean:

```bash
poetry run ruff check <changed files>
```

`black` and `ruff format` are configured with `line-length = 132` in
`pyproject.toml`. Some long-lived modules predate the current settings, so
`black --check` reports findings unrelated to your change. Format only the
lines you touched; reformatting a whole module turns a small fix into an
unreviewable diff.

**Tests.** Third-party dependencies emit several hundred deprecation warnings
that bury the result; `-p no:warnings` keeps the output readable:

```bash
poetry run pytest tests/test_something.py -p no:warnings -q
```

### Isolated Checkouts for Review and Testing

Reviewing a PR or reproducing a bug against another branch should never
disturb your working clone - most clones carry uncommitted work, and
`git checkout` / `git stash` in the wrong directory loses it. Use
`utils/agent_worktree.py`, a thin wrapper over `git worktree` that handles the
PR plumbing. It is stdlib-only and repository-agnostic.

```bash
python utils/agent_worktree.py new --pr 3219      # resolve PR head via gh, fetch, branch, check out
python utils/agent_worktree.py new --branch topic # existing remote branch
python utils/agent_worktree.py new --from origin/master --name scratch

python utils/agent_worktree.py list               # flags: main / managed / dirty / pr#N
python utils/agent_worktree.py path pr3219        # for use in $(...)
python utils/agent_worktree.py update pr3219      # re-fetch after the author pushes
python utils/agent_worktree.py remove pr3219      # also drops the branch it created
python utils/agent_worktree.py cleanup            # remove every worktree it created
python utils/agent_worktree.py info               # repo, remotes, virtualenv, dirty state
```

`new --pr N` asks `gh` which fork the head branch lives in, fetches from the
matching remote (or straight from the fork URL if no remote is configured),
creates a local branch tracking it, and prints the path plus the project
virtualenv. Add `--json` to any command for scripted use.

Notes:

* Worktrees default to `~/.cache/agent-worktrees/<repo>/<name>`; override with
  `--base-dir`, `--path`, or `$AGENT_WORKTREE_DIR`.
* Only worktrees created by the tool are ever removed. They are tagged with an
  `agent-meta.json` inside the repository's git admin directory, so nothing
  extra shows up in `git status`.
* `remove` and `cleanup` refuse to discard uncommitted changes or unpushed
  commits; `cleanup` reports what it skipped and why. `--force` overrides.
* Poetry keys virtualenvs by project path, so a fresh worktree has no
  environment of its own. Run `poetry run` from your main clone, or use the
  interpreter reported by `info`.

Tests live in `tests/test_agent_worktree.py` and run against throwaway local
repositories - no network, credentials or CAPE configuration required.

### Codebase Gotchas

Behaviours that regularly cause silent, hard-to-debug failures:

* **`lib/cuckoo/common/dictionary.py`** - `Dictionary.__getattr__` returns
  `None` for missing keys instead of raising. Consequently
  `getattr(section, "key", default)` **never applies its default**; use
  `section.get("key", default)`.
* **`lib/cuckoo/common/config.py`** - `_BaseConfig.get(section)` takes exactly
  one argument and raises `CuckooOperationalError` for an unknown section, so
  `conf.get(name, default)` is a `TypeError`, not a fallback. `Config` is
  cached per configuration file by its metaclass, so repeated
  `Config("processing")` calls are cheap.
* **`lib/cuckoo/common/integrations/utils.py`** - `run_tool()` returns
  **stdout only**. Callers that need stderr must pass
  `stderr=subprocess.PIPE` themselves.
* **`lib/cuckoo/common/integrations/file_extra_info_modules/__init__.py`** -
  `extractor_ctx()` wraps extractors in `except Exception: log.exception(...)`.
  A `TypeError` or `NameError` therefore surfaces as an empty result rather
  than a crash; check the log before assuming the logic is wrong.
* Broad `except Exception` around encode/decode helpers hides missing
  module-level imports, which then look like a working fallback path. Verify
  the import exists.

### How to Add a Detection Signature
Signatures live in `modules/signatures/`.
*   **Ref:** `docs/book/src/customization/signatures.rst`

```python
from lib.cuckoo.common.abstracts import Signature

class MyMalware(Signature):
    name = "my_malware_behavior"
    description = "Detects specific bad behavior"
    severity = 3
    categories = ["trojan"]
    authors = ["You"]
    minimum = "2.0"

    def run(self):
        # Helper methods: check_file, check_key, check_mutex, check_api, check_ip, check_domain
        return self.check_file(pattern=".*evil\\.exe$", regex=True)
    
    # For performance, use evented signatures (on_call) for high-volume API checks
    # evented = True
    # def on_call(self, call, process): ...
```

### How to Add a Processing Module
Processing modules (`modules/processing/`) run after analysis to extract specific data.
*   **Ref:** `docs/book/src/customization/processing.rst`

```python
from lib.cuckoo.common.abstracts import Processing

class MyExtractor(Processing):
    def run(self):
        self.key = "my_data" # Key in the final report JSON
        result = {}
        # Access raw data via self.analysis_path, self.log_path, etc.
        return result
```

### How to Add a Reporting Module
Reporting modules (`modules/reporting/`) consume the processed data (Global Container).
*   **Ref:** `docs/book/src/customization/reporting.rst`

```python
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class MyReport(Report):
    def run(self, results):
        # 'results' is the big dictionary containing all processed data
        try:
            # Write to file or database
            pass
        except Exception as e:
            raise CuckooReportError(f"Failed to report: {e}")
```

### How to Add a Machinery Module
Machinery modules (`modules/machinery/`) control the virtualization layer.
*   **Ref:** `docs/book/src/customization/machinery.rst`

```python
from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

class MyHypervisor(Machinery):
    def start(self, label):
        # Start the VM
        pass

    def stop(self, label):
        # Stop the VM
        pass
```

### How to Add an Analysis Package
Packages (`analyzer/windows/modules/packages/`) define how to execute the sample inside the VM.
*   **Ref:** `docs/book/src/customization/packages.rst`

```python
from lib.common.abstracts import Package

class MyPackage(Package):
    def start(self, path):
        args = self.options.get("arguments")
        # 'execute' handles injection and monitoring
        return self.execute(path, args, suspended=False)
```

## 6. Best Practices

### Web & UI
1.  **Conditionally Render:** Always check if a dictionary key exists in templates (`{% if analysis.key %}`) before rendering to avoid UI breaks on different analysis types (Static vs Dynamic).
2.  **Keep Views Light:** Perform heavy data crunching in `modules/processing`, not in Django views.
3.  **Modular CSS/JS:** Keep custom styles in `web/static/` rather than inline in templates when possible.

### Performance
1.  **Evented Signatures:** Use `evented = True` and `on_call()` in signatures to process API calls in a single loop instead of iterating the whole log multiple times.
2.  **Ram-boost:** Enable `ram_boost` in `processing.conf` behavior section to keep API logs in memory if the Host has >20GB RAM.
3.  **Disable Unused Reports:** Disable heavy reporting modules (e.g., HTML, MAEC) in `reporting.conf` if not strictly needed for automation.

### Security
1.  **Guest Isolation:** Always use static IPs and consider isolated/host-only networks. Disable noisy services (LLMNR, Teredo) in Guest to reduce PCAP noise.
2.  **Stealth:** Use the `no-stealth` option sparingly. CAPE's anti-anti-VM features are enabled by default and are critical for modern malware.

## 7. Troubleshooting & Debugging
*   **Ref:** `docs/book/src/Issues/Debugging_VM_issues.rst` (VM hangs, High CPU)
*   **Ref:** `docs/book/src/installation/guest/troubleshooting.rst` (Network, Agent issues)

### Common Issues
*   **"Waiting for container":** Check `conf/cuckoo.conf` (IPs) or network configuration. Ensure `cape-rooter` is running if routing is enabled.
*   **VM Stuck/Hanging:**
    *   Check `ps aux | grep qemu` or `grep python`.
    *   **100% CPU:** Livelock.
    *   **0% CPU:** Waiting for I/O (likely network or agent).
    *   Check `lib/cuckoo/core/guest.py` timeouts.
*   **Permissions:** Ensure `cape` user owns the directories and files.
*   **Database Migrations:** If DB errors occur, run `cd utils/db_migration && poetry run alembic upgrade head`.

### Advanced Debugging (py-spy)
If the Python controller is unresponsive, use `py-spy` to inspect the stack trace without stopping the process:
1.  **Install:** `pip install py-spy`
2.  **Dump:** `sudo py-spy dump --pid <PYTHON_PID>`
3.  **Analyze:** Look for `wait_for_completion` (waiting for Guest/Agent) or network calls like `select`, `poll`, `recv` that may be blocked.

### Important Commands
*   **Start CAPE:** `sudo -u cape poetry run python cuckoo.py`
*   **Debug Mode:** `sudo -u cape poetry run python cuckoo.py -d`
*   **Reprocess Task:** `sudo -u cape poetry run python utils/process.py -r <task_id>`
*   **Clean All:** `sudo -u cape poetry run python utils/cleaners.py --clean` (Destructive!)
*   **Download Signatures:** `sudo -u cape poetry run python utils/community.py -waf`
*   **Test Rooter:** `sudo python3 utils/rooter.py -g cape -v`
*   **Check Out a PR Safely:** `python utils/agent_worktree.py new --pr <pr_id>` (isolated worktree; your clone is untouched)

### Database Querying (MongoDB)
CAPE stores unstructured analysis results in the `analysis` collection.
```bash
mongo cuckoo
db.analysis.find({"info.id": 123}, {"behavior.summary": 1}).pretty()
```