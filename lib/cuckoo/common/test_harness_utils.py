import os
import json
import sys
import logging
import zipfile
from typing import Any, List, Optional, Union, Tuple, Dict
import importlib.util

from sqlalchemy import exc

log = logging.getLogger(__name__)

class TestLoader():
    def __init__(self, tests_directory):
        if not os.path.exists(tests_directory):
            raise ValueError(f"Tests directory '{tests_directory}' does not exist.")
        self.tests_root = tests_directory
    
    def load_module(self, module_path):
        module_name = "test_py_module"
        spec = importlib.util.spec_from_file_location(module_name, str(module_path))        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        if not hasattr(module, 'CapeDynamicTest'):
            log.warning(str(dir(module)))
            raise ValueError(f"Module has no CapeDynamicTest class")                
        tester = module.CapeDynamicTest()        

        if not hasattr(tester, 'get_metadata'):
            raise ValueError(f"CapeDynamicTest from {module_path} lacks get_metadata() function")
        return tester

    def validate_test_directory(self, test_path: str) -> Dict[str, Any]:
        """
        Validates a single test directory and returns the metadata from the test module.
        Raises ValueError if the anything is invalid.
        """
        test_metadata = {}
        payload_path = os.path.join(test_path, "payload.zip")
        module_path = os.path.join(test_path, "test.py")
        test_metadata['payload_path'] = payload_path
        test_metadata['module_path'] = module_path

        # 1. Check for required files
        if not os.path.exists(payload_path):
            raise ValueError(f"Missing payload.zip in {payload_path}")
        if not os.path.exists(module_path):
            raise ValueError(f"Missing test.py in {module_path}")

        # 2. Load and instantiate the test module and fetch metadata
        try:
            tester = self.load_module(module_path)                
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

        if 'Name' not in test_metadata['info']:
            raise ValueError(f"Metadata in {module_path} missing 'Name' field")
        if 'Package' not in test_metadata['info']:
            raise ValueError(f"Metadata in {module_path} missing 'Package' field")

        # 3. Verify payload ZIP integrity
        zip_password = test_metadata['info'].get("Zip Password", None)
        try:
            with zipfile.ZipFile(payload_path, 'r') as z:
                # If a password is provided in JSON, verify we can access the list
                if zip_password:
                    z.setpassword(zip_password.encode())
                # Test if the zip is actually readable/not corrupt
                z.testzip() 
        except zipfile.BadZipFile:
            if zip_password:
                raise ValueError(f"{payload_path} is not usable with the given password")
            else:
                raise ValueError(f"{payload_path} is corrupt")
            
        # 4. Return prepared metadata for DB ingest
        return test_metadata


    def load_tests(self) -> List[Dict[str, Any]]:
        """
        Walks the root directory and yields validated test configurations.
        """
        available_tests = []
        unavailable_tests = []
        
        if not os.path.exists(self.tests_root):
            log.error(f"Tests root {self.tests_root} does not exist.")
            return []

        for entry in os.scandir(self.tests_root):
            if not entry.is_dir():
                continue

            try:
                test_config = self.validate_test_directory(entry.path)
                available_tests.append(test_config)
                log.info("Loaded test: %s",test_config['info']['Name'])
            except Exception as e:
                log.warning(f"Skipping directory {entry.path} due to exception")
                log.exception("Verify exception %s",e)
                unavailable_tests.append({"module_path":entry.path, "error":str(e)})

        return {'available':available_tests, 'unavailable': unavailable_tests}

class TestResultValidator():
    def __init__(self, test_directory: str):
        report_path = os.path.join(test_directory, "reports/report.json")
        try:
            self.report = json.load(open(report_path, 'r'))
        except Exception as e:
            raise ValueError(f"Failed to load {report_path}: {e}")
            self.report = None