import sys
import unittest
import pytest

import lib

from lib.core.packages import Package

@pytest.fixture
def patch_netlogfile(monkeypatch):
    class MockNetlogFile:
        def init(self, *args):
            return
        def close(self):
            return
    monkeypatch.setattr(lib.core.packages, "NetlogFile", MockNetlogFile)
    monkeypatch.setattr(lib.core.packages, "append_buffer_to_host", lambda *args: None)
    yield

class TestPackage(unittest.TestCase):

    @pytest.mark.usefixtures("patch_netlogfile")
    def test_package_init_args(self):
        pkg = Package(sys.executable, options={})
        self.assertEqual(pkg.args, [])

    @pytest.mark.usefixtures("patch_netlogfile")
    def test_package_init_args_list(self):
        pkg = Package(sys.executable, options={"arguments": ["foo", "bar"]})
        self.assertEqual(pkg.args, ["foo", "bar"])

    @pytest.mark.usefixtures("patch_netlogfile")
    def test_package_init_args_str(self):
        pkg = Package(sys.executable, options={"arguments": "foo bar"})
        self.assertEqual(pkg.args, ["foo", "bar"])
