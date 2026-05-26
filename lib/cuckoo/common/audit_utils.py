import os
import logging
import zipfile
import shutil
from pathlib import Path
from typing import Any, List, Dict
import importlib.util
from lib.cuckoo.core.data import task as db_task
from lib.cuckoo.core.data.audit_data import TEST_RUNNING, TEST_COMPLETE, TEST_FAILED, TEST_QUEUED

log = logging.getLogger(__name__)

def load_module(module_path):
    module_name = "test_py_module"
    spec = importlib.util.spec_from_file_location(module_name, str(module_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, 'CapeDynamicTest'):
        log.warning(str(dir(module)))
        raise ValueError("Module has no CapeDynamicTest class")
    tester = module.CapeDynamicTest()

    if not hasattr(tester, 'get_metadata'):
        raise ValueError(f"CapeDynamicTest from {module_path} lacks get_metadata() function")
    return tester


class TestLoader():
    def __init__(self, tests_directory):
        if not os.path.exists(tests_directory):
            raise ValueError(f"Tests directory '{tests_directory}' does not exist.")
        self.tests_root = tests_directory

    def _extract_payload(self, payload_archive, payload_output_dir, zip_password=None):

        # Verify payload ZIP integrity
        try:
            with zipfile.ZipFile(payload_archive, 'r') as z:
                # If a password is provided in JSON, verify we can access the list
                if zip_password:
                    z.setpassword(zip_password.encode())
                # Test if the zip is actually readable/not corrupt
                z.testzip()
        except zipfile.BadZipFile:
            if zip_password:
                raise zipfile.BadZipFile(f"{payload_archive} is not usable with the given password")
            else:
                raise zipfile.BadZipFile(f"{payload_archive} is corrupt")

        # delete the unwrapped payload in case a new zip has been uploaded
        if os.path.exists(payload_output_dir):
            shutil.rmtree(payload_output_dir)

        with zipfile.ZipFile(payload_archive, 'r') as zip_ref:
            if zip_password:
                zip_ref.extractall(payload_output_dir, pwd=zip_password)
            else:
                zip_ref.extractall(payload_output_dir)

        payload_path = None
        if not os.path.isdir(payload_output_dir):
            raise NotADirectoryError("Bad payload directory extracted")

        dir_path = Path(payload_output_dir)
        dir_contents = list(dir_path.iterdir())
        if not dir_contents:
            raise FileNotFoundError("Nothing in extracted payload directory")

        if len(dir_contents) == 1:
            payload_path = str(dir_contents[0])
        else:
            # If multiple items, treat the directory itself as the payload
            payload_path = payload_output_dir

        if not os.path.exists(payload_path):
            raise FileNotFoundError("Nothing extracted from payload archive or it could not be written to disk")

        return payload_path

    def validate_test_directory(self, test_path: str) -> Dict[str, Any]:
        """
        Validates a single test directory and returns the metadata from the test module.
        Raises ValueError if the anything is invalid.
        """
        payload_archive = os.path.join(test_path, "payload.zip")
        module_path = os.path.join(test_path, "test.py")

        # Check for required files
        if not os.path.exists(payload_archive):
            raise ValueError(f"Missing payload.zip in {payload_archive}")
        if not os.path.exists(module_path):
            raise ValueError(f"Missing test.py in {module_path}")

        test_metadata = {}
        test_metadata['module_path'] = module_path

        # Load and instantiate the python test module and fetch metadata
        try:
            tester = load_module(module_path)
            test_metadata['info'] = tester.get_metadata()

            test_metadata['objectives'] = []

            def load_objective(objective):
                objdict = {'name': objective.name,
                         'requirement': objective.requirement,
                         'children': [load_objective(child) for child in objective.children]
                         }
                return objdict
            for objective in tester.get_objectives():
                test_metadata['objectives'].append(load_objective(objective))

        except Exception as e:
            raise ValueError(f"Failed to load test module or fetch metadata from {module_path}: {e}")

        conf = test_metadata['info'].get("Task Config", None)
        if conf:
            if conf.get("Request Options",None) is None:
                test_metadata['info']["Request Options"] = ""

        if 'Name' not in test_metadata['info']:
            raise ValueError(f"Metadata in {module_path} missing 'Name' field")
        if 'Package' not in test_metadata['info']:
            raise ValueError(f"Metadata in {module_path} missing 'Package' field")

        zip_password = test_metadata['info'].get("Zip Password", None)
        payload_output_dir = os.path.join(test_path, "payload")
        test_metadata['payload_path'] = self._extract_payload(payload_archive, payload_output_dir, zip_password)

        # Return prepared metadata for DB ingest
        return test_metadata

    def load_tests(self) -> List[Dict[str, Any]]:
        """
        Walks the root directory and yields validated test configurations.
        """
        available_tests = []
        unavailable_tests = []

        if not os.path.exists(self.tests_root):
            log.error("Tests root %s does not exist.", self.tests_root)
            return {"error": f"Tests root {self.tests_root} does not exist."}

        for entry in os.scandir(self.tests_root):
            if entry.is_dir():
                test_config = None
                try:
                    test_config = self.validate_test_directory(entry.path)
                    available_tests.append(test_config)
                    log.info("Loaded test: %s",test_config['info']['Name'])
                except Exception as e:
                    log.exception("Skipping directory %s due to exception",entry.path)
                    unavailable_tests.append({"module_path":entry.path, "error":str(e)})

        return {'available':available_tests, 'unavailable': unavailable_tests}


class TestResultValidator():
    def __init__(self, test_module_path:str, task_storage_directory: str):
        if os.path.isdir(task_storage_directory):
            self.task_directory = task_storage_directory
        else:
            raise NotADirectoryError(f"Invalid task directory: {task_storage_directory}")

        try:
            self.test_module = load_module(test_module_path)
        except Exception as e:
            raise ValueError(f"Failed to load test evaluation module {test_module_path}: {e}")

    def evaluate(self):
        self.test_module.evaluate_results(self.task_directory)
        return self.test_module.get_results()

def task_status_to_run_status(cape_task_status):
    if cape_task_status == db_task.TASK_REPORTED:
        return TEST_COMPLETE
    if cape_task_status == db_task.TASK_PENDING:
        return TEST_QUEUED
    if cape_task_status in [db_task.TASK_RUNNING,
                            db_task.TASK_DISTRIBUTED,
                            db_task.TASK_RECOVERED,
                            db_task.TASK_COMPLETED,
                            db_task.TASK_DISTRIBUTED_COMPLETED]:
        return TEST_RUNNING
    if cape_task_status in [db_task.TASK_BANNED,
                            db_task.TASK_FAILED_ANALYSIS,
                            db_task.TASK_FAILED_PROCESSING,
                            db_task.TASK_FAILED_REPORTING
                            ]:
        return TEST_FAILED

    raise Exception(f"Unknown cape task status: {cape_task_status}")
