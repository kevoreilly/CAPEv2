import logging
import os
import sys

logging.basicConfig(level=logging.DEBUG)

testfile_dir = os.path.dirname(__file__)
testfile_dir = os.path.join(testfile_dir, "..", "..", "analyzer", "windows")
sys.path.append(testfile_dir)

import modules.packages.zip as zip

extract_dir = os.path.expandvars("%USERPROFILE%\\Desktop")


def test_zip_Extraction():
    zip_obj = zip.Zip()
    zip_obj.extract_zip("./files/test_zip.zip", extract_dir)


def test_zip_JSON():
    zip_obj = zip.Zip()
    f = zip_obj.process_unzipped_contents(extract_dir, "test_executable.exe")
    print(f)
