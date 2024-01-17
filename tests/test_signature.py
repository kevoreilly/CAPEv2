import pytest
import os
import json
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.core.plugins import RunSignatures
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.plugins import register_plugin, list_plugins

class FakeSignature(Signature):
    name = "Fake"
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

class TestSignatureEngine:
    def setup_method(self, method):
        self.d = Database(dsn="sqlite://")
        register_plugin("signatures", FakeSignature)
        
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
            # Single signature which should match
            (
                1,
                "Fake",
                True,
            ),
            # Single signature which shouldn't match
            (
                2,
                "Fake",
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
    # This test can be used to validate if a specific report trigger your function the same way as process.py does. It could be used to test a suite of signature against known report.json files.
    def test_RunSignatures(self, task_id, signature_name, match_expected):
        task = {}
        task["id"] = task_id
        report = None
        results = {}
        if task_id is not None:
            report = os.path.join(CUCKOO_ROOT, "tests", "data", str(task_id), "reports", "report.json")
            assert(not path_exists(report),"Missing test data file, failing")
        if report:
            results = json.load(open(report))
            assert(results is not None,"Test data file is empty")
        # If the "statistics" key-value pair has not been set by now, set it here
        if "statistics" not in results:
            results["statistics"] = {"signatures": []}
        RunSignatures(task=task, results=results).run(signature_name)
        if match_expected:
            assert(signature_name in results["signatures"],"Signature should be matching report")
            assert(len(results["signatures"]) == 1,"{signature_name} should be the only signature ran") 
        elif not match_expected:
            assert(signature_name not in results["signatures"],"Signature should not be matching report")
            assert(len(results["signatures"]) == 0,"{signature_name} should have no signature matching")
            
