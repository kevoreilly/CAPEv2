import pytest
import os
import json
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.core.plugins import RunSignatures
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.plugins import register_plugin


class FakeSignatureNonFiltered(Signature):
    name = "FakeSig"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["cccs-mog"]
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

class FakeSignatureFiltered(Signature):
    name = "FakeSigFiltered"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["cccs-mog"]
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
    authors = ["cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["gethostbyname"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query_host = False

    def on_call(self, call, process):
        if call["api"] == "gethostbyname":
            self.query_host = True
            

    def on_complete(self):
        if self.query_host:
            return True
        
class FakeSignatureProcess(Signature):
    name = "FakeProcess"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_processnames = set(["powershell.exe"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query_process = False

    def on_call(self, call, process):
        if process["process_name"] == "powershell.exe":
            self.query_process = True
            

    def on_complete(self):
        if self.query_process:
            return True
        
class FakeSignatureCategory(Signature):
    name = "FakeCategory"
    description = "Fake signature created for testing signatures triggering"
    severity = 1
    categories = ["malware"]
    authors = ["cccs-mog"]
    minimum = "1.3"
    evented = True

    filter_categories = set(["network"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.query_network = False

    def on_call(self, call, process):
        if call["category"] == "network":
            self.query_network = True
            

    def on_complete(self):
        if self.query_network:
            return True

class TestSignatureEngine:
    def setup_method(self, method):
        self.d = Database(dsn="sqlite://")
        register_plugin("signatures", FakeSignatureAPI)
        register_plugin("signatures", FakeSignatureProcess)
        register_plugin("signatures", FakeSignatureCategory)
        register_plugin("signatures", FakeSignatureNonFiltered)
        register_plugin("signatures", FakeSignatureFiltered)

    @pytest.mark.parametrize(
        "task_id, signature_name, match_expected",
        # @task_id: task to be created or task id to use
        # @signature_name: Name of the signature to test
        # @match_expected: tell if the signature should match or not the report
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
                "FakeSig",
                True,
            ),
            # Single signature with all filtering  which should match
            (
                2,
                "FakeSig",
                False,
            ),
            # Single signature with all double filtering which should match
            (
                1,
                "FakeSigFiltered",
                True,
            ),
            # Single signature with all double filtering which shouldn't match
            (
                2,
                "FakeSigFiltered",
                False,
            ),
            # Test running all signatures
            (
                2,
                None,
                False,
            ),
        ),
    )
    # This test can be used to validate if a specific report trigger your function the same way as process.py does. 
    # It could be used to test a suite of signature against known report.json files.
    def test_RunSignatures(self, task_id, signature_name, match_expected):
        task = {}
        task["id"] = task_id
        report = None
        results = {}
        if task_id is not None:
            report = os.path.join(CUCKOO_ROOT, "tests", "test_data", str(task_id), "reports", "report.json")
            assert path_exists(report),"Missing test data file, failing"
        if report:
            results = json.load(open(report))
            assert results is not None,"Test data file is empty"
        # If the "statistics" key-value pair has not been set by now, set it here
        RunSignatures(task=task, results=results).run(signature_name)
        if match_expected:
            assert signature_name in results["statistics"]["signatures"][0]["name"],"Signature should be matching report"
            assert len(results["statistics"]["signatures"]) == 1,"{signature_name} should be the only signature ran"
        elif not match_expected:
            assert signature_name not in results["signatures"],"Signature should not be matching report"
            assert len(results["signatures"]) == 0,"{signature_name} should have no signature matching"
            
