# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

import lib.cuckoo.common.abstracts as abstracts
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.path_utils import path_exists


@pytest.fixture
def proc():
    return abstracts.Processing()


class TestProcessing:
    def test_not_implemented_run(self, proc):
        with pytest.raises(NotImplementedError):
            proc.run()


@pytest.fixture
def sig():
    return abstracts.Signature()


class TestSignature:
    def test_not_implemented_run(self, sig):
        with pytest.raises(NotImplementedError):
            sig.run()

    def test_missing_key_domain(self, sig):
        """Test with domain key missing."""
        sig.results = {"network": {}}
        assert sig.check_domain("*") is None


@pytest.fixture
def rep():
    return abstracts.Report()


class TestReport:
    def test_set_path(self, rep):
        dir = tempfile.mkdtemp()
        rep_dir = os.path.join(dir, "reports")
        rep.set_path(dir)
        assert path_exists(rep_dir)
        os.rmdir(rep_dir)

    def test_options_none(self, rep):
        assert rep.options is None

    def test_set_options_assignment(self, rep):
        foo = {1: 2}
        rep.set_options(foo)
        assert rep.options == foo

    def test_not_implemented_run(self, rep):
        with pytest.raises(NotImplementedError):
            rep.run()


@pytest.mark.usefixtures("db")
class TestScreenshotMachinery:
    def test_missing_screenshot_method(self):
        class MockMachinery(abstracts.Machinery):
            module_name = "mock"

            def read_config(self):
                return {"mock": {"machines": []}}

            def _list(self):
                pass

        tm = MockMachinery()
        mock_cuckoo_cfg = MagicMock()
        mock_cuckoo_cfg.machinery_screenshots = True

        with patch.object(abstracts.cfg, "cuckoo", mock_cuckoo_cfg):
            # calling _initialize_check() raises without any methods
            with pytest.raises(CuckooCriticalError):
                tm._initialize_check()

    def test_machinery_missing_screenshot_support(self):
        class MockMachinery(abstracts.Machinery):
            module_name = "mock"

            def read_config(self):
                return {"mock": {"machines": []}}

            def _list(self):
                pass

        tm = MockMachinery()
        mock_cuckoo_cfg = MagicMock()
        mock_cuckoo_cfg.machinery_screenshots = True

        with patch.object(abstracts.cfg, "cuckoo", mock_cuckoo_cfg):
            # calling _initialize_check() raises without providing a screenshot() impl
            with pytest.raises(CuckooCriticalError):
                tm._initialize_check()

    def test_machinery_screenshot_support(self):
        class MockMachinery(abstracts.Machinery):
            module_name = "mock"

            def read_config(self):
                return {"mock": {"machines": []}}

            def _list(self):
                pass

            def screenshot(self):
                return True

        tm = MockMachinery()
        mock_cuckoo_cfg = MagicMock()
        mock_cuckoo_cfg.machinery_screenshots = True
        with patch.object(abstracts.cfg, "cuckoo", mock_cuckoo_cfg):
            # calling _initialize_check() succeeds, a screenshot() impl is provided
            tm._initialize_check()
        assert tm.screenshot()
