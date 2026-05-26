.. _audit_framework:

===============
Audit Framework
===============

The Audit Framework is a specialized subsystem within CAPE designed to verify the correctness and reliability of the sandbox's analysis capabilities. It allows operators to define specific test cases ("Audit Packages") that run known samples with expected behavioral outcomes ("Objectives"). This is particularly useful for validating that CAPE is correctly capturing specific behaviors (e.g., shellcode injection, network beacons) after updates or configuration changes.

Concepts
========

* **Available Test**: A test case definition stored on the disk. It consists of a payload (e.g., a malware sample) and a Python script defining the success criteria.
* **Test Session**: A collection of test runs. You can group multiple tests into a session to validate a specific aspect of the system (e.g., "Weekly Regression Test").
* **Test Run**: A single execution of an *Available Test* within a *Test Session*. It links to a standard CAPE Task ID.
* **Objective**: A specific criterion that must be met for a test to pass (e.g., "DNS request to evil.com observed", "File dropped in AppData").

Configuration
=============

To enable the Audit Framework, ensure the feature is enabled in your web configuration.

Edit ``conf/web.conf``:

.. code-block:: ini

    [audit_framework]
    enabled = yes

The framework looks for test packages in ``tests/audit_packages/`` by default.

Creating Audit Packages
=======================

Audit packages are directory-based. Each package must be a subdirectory inside ``tests/audit_packages/`` (or the configured path) containing at least two files:

1. ``payload.zip``: A zip file containing the sample to be analyzed.
   * *Note*: If the zip contains a single file, that file is treated as the payload. If it contains multiple files, the extracted directory is treated as the payload (useful for packages requiring dependencies).
2. ``test.py``: A Python script defining the test metadata, objectives, and evaluation logic.

Directory Structure Example
---------------------------

.. code-block:: text

    tests/audit_packages/
    ├── Emotet_Network_Beacon/
    │   ├── payload.zip
    │   └── test.py
    └── AsyncRAT_Config_Extract/
        ├── payload.zip
        └── test.py

The ``test.py`` Structure
-------------------------

The Python script must define a class named ``CapeDynamicTest`` that implements the following methods:

* ``get_metadata()``: Returns a dictionary of test settings.
* ``get_objectives()``: Returns a list of objective objects.
* ``evaluate_results(task_dir)``: Analyzes the analysis results.
* ``get_results()``: Returns the final status of objectives.

**Example `test.py`:**

.. code-block:: python

    import os
    import json

    class TestObjective:
        def __init__(self, name, requirement, children=None):
            self.name = name
            self.requirement = requirement
            self.children = children or []

    class CapeDynamicTest:
        def __init__(self):
            self._results = {}

        def get_metadata(self):
            """
            Define high-level test information.
            """
            return {
                "Name": "Emotet Beacon Test",
                "Description": "Verifies that CAPE detects the C2 network connection.",
                "Package": "exe",          # CAPE analysis package to use
                "Timeout": 200,            # Analysis timeout in seconds
                "Zip Password": "infected" # Password for payload.zip (optional)
            }

        def get_objectives(self):
            """
            Define the criteria for success.
            """
            return [
                TestObjective("network_c2", "Must connect to C2 server 1.2.3.4"),
                TestObjective("dropped_payload", "Must drop the second stage loader")
            ]

        def evaluate_results(self, task_dir):
            """
            Parse the CAPE report to verify objectives.
            task_dir: Path to the storage directory for this task (contains report.json, etc.)
            """
            report_path = os.path.join(task_dir, "reports", "report.json")
            
            # Default state
            self._results = {
                "network_c2": {"state": "failure", "state_reason": "IP not found"},
                "dropped_payload": {"state": "failure", "state_reason": "File not found"}
            }

            if not os.path.exists(report_path):
                return

            with open(report_path, "r") as f:
                report = json.load(f)

            # Check Network
            for host in report.get("network", {}).get("hosts", []):
                if host == "1.2.3.4":
                    self._results["network_c2"] = {"state": "success", "state_reason": "Connection found"}

            # Check Dropped Files
            if "dropped" in report:
                self._results["dropped_payload"] = {"state": "success", "state_reason": "Dropped files present"}

        def get_results(self):
            """
            Return the dictionary of results calculated in evaluate_results.
            Keys must match the Objective names.
            """
            return self._results

Web Interface Usage
===================

Access the Audit interface via the sidebar menu or at ``/audit/``.

1. **Manage Tests**:
   The main dashboard lists all available tests.
   * If you have added new tests to the disk, click **Reload Tests** to update the database.

2. **Create Session**:
   * Select the checkboxes next to the tests you wish to run.
   * Click **Create Session**.
   * You will be redirected to the Session view.

3. **Run Audit**:
   * In the Session view, you can see the status of each test (Unqueued, Queued, Running, Complete).
   * Click **Queue All** to submit all unqueued tests to CAPE.
   * The status will update automatically as CAPE processes the tasks.

4. **View Results**:
   * Once a test is ``Complete``, the framework automatically runs the ``evaluate_results`` logic from your `test.py`.
   * The UI will display a **Pass** (Green) or **Fail** (Red) badge for each objective.
   * You can expand a test row to see detailed reasons for failure or success.
