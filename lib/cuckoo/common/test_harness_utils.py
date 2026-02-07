import os
import json
import sys
import logging
import zipfile
import shutil
from pathlib import Path
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
                raise ValueError(f"{payload_archive} is not usable with the given password")
            else:
                raise ValueError(f"{payload_archive} is corrupt")

        try:
            # delete the unwrapped payload in case a new zip has been uploadedd
            if os.path.exists(payload_output_dir):
                shutil.rmtree(payload_output_dir)
            with zipfile.ZipFile(payload_archive, 'r') as zip_ref:
                if zip_password:
                    zip_ref.extractall(payload_output_dir, pwd=zip_password)
                else:
                    zip_ref.extractall(payload_output_dir)                    
        except Exception as ex:
            raise Exception(f"Failed to extract {payload_archive} to {payload_output_dir}: {ex}")

        payload_path = None
        try:
            dir_path = Path(payload_output_dir)
            payload_path = str(next(dir_path.iterdir()))
        except Exception as e:
            raise Exception(f"Failed to get a payload from extracted payload archive: {e}");
        
        if not os.path.exists(payload_path):
            raise FileNotFoundError(f"Nothing extracted from payload archive or it could not be written to disk");

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

        conf = test_metadata['info'].get("Task Config", None)
        if conf:
            if conf.get("Request Options",None) == None:
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
            raise ValueError(f"Failed to load report {report_path}: {e}")
            self.report = None