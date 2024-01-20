import json
import os

import pytest

from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.core.plugins import RunSignatures, register_plugin


class FakeSignatureCallAlways(Signature):
    name = "FakeSignatureCallAlways"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["@CybercentreCanada", "@cccs-mog"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query = False

    def on_call(self, call, process):
        self.query = True

    def on_complete(self):
        if self.query:
            return True


class FakeSignatureAPI_Cat(Signature):
    name = "FakeSignatureAPI_Cat"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["@CybercentreCanada", "@cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["gethostbyname"])
    filter_categories = set(["network"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query = False

    def on_call(self, call, process):
        self.query = True

    def on_complete(self):
        if self.query:
            return True


class FakeSignatureAPI_Process(Signature):
    name = "FakeSignatureAPI_Process"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["@CybercentreCanada", "@cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["gethostbyname"])
    filter_processnames = set(["powershell.exe"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query = False

    def on_call(self, call, process):
        self.query = True

    def on_complete(self):
        if self.query:
            return True


class FakeSignatureCat_Process(Signature):
    name = "FakeSignatureCat_Process"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["@CybercentreCanada", "@cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_processnames = set(["powershell.exe"])
    filter_categories = set(["network"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query = False

    def on_call(self, call, process):
        self.query = True

    def on_complete(self):
        if self.query:
            return True


class FakeSignatureAPI_Cat_Process_With_No_OnCall_Check(Signature):
    name = "FakeSignatureAPI_Cat_Process_With_No_OnCall_Check"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["@CybercentreCanada", "@cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["gethostbyname"])
    filter_processnames = set(["powershell.exe"])
    filter_categories = set(["network"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query = False

    def on_call(self, call, process):
        self.query = True

    def on_complete(self):
        if self.query:
            return True


class FakeSignatureAPI_Cat_Process_With_OnCall_Check(Signature):
    name = "FakeSignatureAPI_Cat_Process_With_OnCall_Check"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["@CybercentreCanada", "@cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["gethostbyname"])
    filter_processnames = set(["powershell.exe"])
    filter_categories = set(["network"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query = False

    def on_call(self, call, process):
        if call["api"] == "gethostbyname" and call["category"] == "network" and process["process_name"] == "powershell.exe":
            self.query = True

    def on_complete(self):
        if self.query:
            return True


class FakeSignatureAPI(Signature):
    name = "FakeAPI"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["@CybercentreCanada", "@cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["gethostbyname"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query_host = False

    def on_call(self, call, process):
        self.query_host = True

    def on_complete(self):
        if self.query_host:
            return True


class FakeSignatureProcess(Signature):
    name = "FakeProcess"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["@CybercentreCanada", "@cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_processnames = set(["powershell.exe"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query_process = False

    def on_call(self, call, process):
        self.query_process = True

    def on_complete(self):
        if self.query_process:
            return True


class FakeSignatureCategory(Signature):
    name = "FakeCategory"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["@CybercentreCanada", "@cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_categories = set(["network"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query_network = False

    def on_call(self, call, process):
        self.query_network = True

    def on_complete(self):
        if self.query_network:
            return True


class TestSignatureEngine:
    def setup_class(cls):
        sigs = [
            FakeSignatureAPI,
            FakeSignatureProcess,
            FakeSignatureCategory,
            FakeSignatureAPI_Cat_Process_With_OnCall_Check,
            FakeSignatureAPI_Cat_Process_With_No_OnCall_Check,
            FakeSignatureCallAlways,
            FakeSignatureAPI_Cat,
            FakeSignatureAPI_Process,
            FakeSignatureCat_Process,
        ]
        for sig in sigs:
            register_plugin("signatures", sig)

    @pytest.mark.parametrize(
        "task_id, signature_name, match_expected",
        # @task_id: task to be created or task id to use
        # @signature_name: Name of the signature to test
        # @match_expected: tell if the signature should match or not in the report (if multiple specify which ones if wanted)
        (
            # No tasks and signature_name
            (
                None,
                "",
                False,
            ),
            # Single signature with API filtering which should match
            (
                1,
                "FakeAPI",
                True,
            ),
            # Single signature with API filtering which shouldn't match
            (
                2,
                "FakeAPI",
                False,
            ),
            # Single signature with category filtering  which should match
            (
                2,
                "FakeCategory",
                True,
            ),
            # Single signature with category filtering  which shouldn't match
            (
                3,
                "FakeCategory",
                False,
            ),
            # Single signature with process filtering  which should match
            (
                2,
                "FakeProcess",
                True,
            ),
            # Single signature with process filtering  which shouldn't match
            (
                3,
                "FakeProcess",
                False,
            ),
            # Single signature with all filtering  which should match
            (
                1,
                "FakeSignatureAPI_Cat_Process_With_No_OnCall_Check",
                True,
            ),
            # Single signature with all filtering  which should match
            (
                2,
                "FakeSignatureAPI_Cat_Process_With_No_OnCall_Check",
                False,
            ),
            # Single signature with all double filtering which should match
            (
                1,
                "FakeSignatureAPI_Cat_Process_With_OnCall_Check",
                True,
            ),
            # Single signature with all double filtering which shouldn't match
            (
                2,
                "FakeSignatureAPI_Cat_Process_With_OnCall_Check",
                False,
            ),
            # Single signature with no filtering which should match
            (
                1,
                "FakeSignatureCallAlways",
                True,
            ),
            # Single signature with two filter which should match
            (
                1,
                "FakeSignatureCat_Process",
                True,
            ),
            # Single signature with two filter which shouldn't match
            (
                3,
                "FakeSignatureCat_Process",
                False,
            ),
            # Single signature with two filter which should match
            (
                1,
                "FakeSignatureAPI_Process",
                True,
            ),
            # Single signature with two filter which shouldn't match
            (
                3,
                "FakeSignatureAPI_Process",
                False,
            ),
            # Single signature with two filter which should match
            (
                1,
                "FakeSignatureAPI_Cat",
                True,
            ),
            # Single signature with two filter which shouldn't match
            (
                3,
                "FakeSignatureAPI_Cat",
                False,
            ),
            # Test running all signatures
            (
                1,
                False,
                [
                    "FakeProcess",
                    "FakeSignatureCallAlways",
                    "FakeSignatureCat_Process",
                    "FakeCategory",
                    "FakeAPI",
                    "FakeSignatureAPI_Cat_Process_With_No_OnCall_Check",
                    "FakeSignatureAPI_Cat_Process_With_OnCall_Check",
                    "FakeSignatureAPI_Process",
                    "FakeSignatureAPI_Cat",
                ],
            ),
            # Test running all signatures
            (
                2,
                False,
                ["FakeProcess", "FakeSignatureCallAlways", "FakeSignatureCat_Process", "FakeCategory"],
            ),
            # Test running all signatures
            (
                3,
                False,
                ["FakeSignatureCallAlways"],
            ),
        ),
    )
    # This test can be used to validate if a specific report trigger your function the same way as process.py does.
    # It could be used to test a suite of signature against known report.json files.
    def test_RunSignatures_run(self, task_id, signature_name, match_expected):
        task = {"id": task_id}
        report = None
        results = {}
        if task_id is not None:
            report = os.path.join(CUCKOO_ROOT, "tests", "test_data", str(task_id), "reports", "report.json")
            assert path_exists(report), "Missing test data file, failing"
        if report:
            results = json.load(open(report))
            assert results is not None, "Test data file is empty"
        # If the "statistics" key-value pair has not been set by now, set it here
        RunSignatures(task=task, results=results).run(signature_name)
        if match_expected and isinstance(match_expected, bool):
            assert signature_name in results["signatures"][0]["name"], f"Signature should be matching report for task {task_id}"
            assert len(results["signatures"]) == 1, f"{signature_name} should be the only signature run"
        elif not match_expected:
            if "statistics" in results.keys():
                assert signature_name not in results["signatures"], f"Signature should not be matching report for task {task_id}"
        else:
            triggered = []
            for sig in results["signatures"]:
                triggered.append(sig["name"])
            for match in match_expected:
                assert match in triggered, "Signature should be matching report"
            assert len(match_expected) == len(results["signatures"]), f"Should have {len(match_expected)} signature matching"
