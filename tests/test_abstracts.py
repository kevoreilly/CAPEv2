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


class TestLibvirtMachineryStop:
    def test_stop_ignores_domain_not_running_race(self, monkeypatch):
        class DummyLibvirtError(Exception):
            pass

        fake_libvirt = MagicMock()
        fake_libvirt.libvirtError = DummyLibvirtError
        monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)
        monkeypatch.setattr(abstracts, "HAVE_LIBVIRT", True)

        machinery = object.__new__(abstracts.LibVirtMachinery)
        machinery._status = MagicMock(return_value=abstracts.LibVirtMachinery.RUNNING)
        machinery._wait_status = MagicMock()

        vm = MagicMock()
        vm.isActive.return_value = True
        vm.destroy.side_effect = DummyLibvirtError("Requested operation is not valid: domain is not running")

        conn = MagicMock()
        conn.lookupByName.return_value = vm
        machinery._connect = MagicMock(return_value=conn)

        # Should not raise CuckooMachineError when domain stopped concurrently
        machinery.stop("win10_1")
        machinery._wait_status.assert_called_once_with("win10_1", abstracts.LibVirtMachinery.POWEROFF)

    def test_stop_reraises_other_libvirt_errors(self, monkeypatch):
        class DummyLibvirtError(Exception):
            pass

        fake_libvirt = MagicMock()
        fake_libvirt.libvirtError = DummyLibvirtError
        monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)
        monkeypatch.setattr(abstracts, "HAVE_LIBVIRT", True)

        machinery = object.__new__(abstracts.LibVirtMachinery)
        machinery._status = MagicMock(return_value=abstracts.LibVirtMachinery.RUNNING)
        machinery._wait_status = MagicMock()

        vm = MagicMock()
        vm.isActive.return_value = True
        vm.destroy.side_effect = DummyLibvirtError("hypervisor connection lost")

        conn = MagicMock()
        conn.lookupByName.return_value = vm
        machinery._connect = MagicMock(return_value=conn)

        with pytest.raises(abstracts.CuckooMachineError, match="Error stopping virtual machine win10_1"):
            machinery.stop("win10_1")


class TestLibvirtMachineryDumpMemory:
    @staticmethod
    def _make_machinery(monkeypatch):
        class DummyLibvirtError(Exception):
            pass

        fake_libvirt = MagicMock()
        fake_libvirt.libvirtError = DummyLibvirtError
        fake_libvirt.VIR_DUMP_MEMORY_ONLY = 1
        monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)
        monkeypatch.setattr(abstracts, "HAVE_LIBVIRT", True)

        machinery = object.__new__(abstracts.LibVirtMachinery)
        vm = MagicMock()
        conn = MagicMock()
        conn.lookupByName.return_value = vm
        machinery._connect = MagicMock(return_value=conn)
        return machinery, vm, fake_libvirt, DummyLibvirtError

    def test_dump_memory_sets_0660_and_libvirt_group(self, tmp_path, monkeypatch):
        machinery, vm, fake_libvirt, _ = self._make_machinery(monkeypatch)
        dump_file = tmp_path / "memory.dmp"

        fake_grp = MagicMock()
        fake_grp.getgrnam.return_value = MagicMock(gr_gid=137)
        monkeypatch.setattr(abstracts, "grp", fake_grp)

        fchown_calls = []
        monkeypatch.setattr(abstracts.os, "fchown", lambda fd, uid, gid: fchown_calls.append((uid, gid)))

        old_umask = os.umask(0o077)
        try:
            machinery.dump_memory("win10_1", str(dump_file))
        finally:
            os.umask(old_umask)

        assert dump_file.exists()
        assert (dump_file.stat().st_mode & 0o777) == 0o660
        fake_grp.getgrnam.assert_called_once_with("libvirt")
        assert fchown_calls == [(-1, 137)]
        vm.coreDump.assert_called_once_with(str(dump_file), flags=fake_libvirt.VIR_DUMP_MEMORY_ONLY)

    def test_dump_memory_falls_back_to_libvirtd_group(self, tmp_path, monkeypatch):
        machinery, vm, fake_libvirt, _ = self._make_machinery(monkeypatch)
        dump_file = tmp_path / "memory.dmp"

        def fake_getgrnam(name):
            if name == "libvirt":
                raise KeyError(name)
            return MagicMock(gr_gid=138)

        fake_grp = MagicMock()
        fake_grp.getgrnam.side_effect = fake_getgrnam
        monkeypatch.setattr(abstracts, "grp", fake_grp)

        fchown_calls = []
        monkeypatch.setattr(abstracts.os, "fchown", lambda fd, uid, gid: fchown_calls.append((uid, gid)))

        machinery.dump_memory("win10_1", str(dump_file))

        assert (dump_file.stat().st_mode & 0o777) == 0o660
        assert fchown_calls == [(-1, 138)]
        vm.coreDump.assert_called_once_with(str(dump_file), flags=fake_libvirt.VIR_DUMP_MEMORY_ONLY)

    def test_dump_memory_tolerates_missing_group_and_permission_error(self, tmp_path, monkeypatch):
        machinery, vm, fake_libvirt, _ = self._make_machinery(monkeypatch)
        dump_file = tmp_path / "memory.dmp"

        fake_grp = MagicMock()
        fake_grp.getgrnam.side_effect = KeyError("missing")
        monkeypatch.setattr(abstracts, "grp", fake_grp)
        machinery.dump_memory("win10_1", str(dump_file))
        assert (dump_file.stat().st_mode & 0o777) == 0o660

        fake_grp.getgrnam.side_effect = None
        fake_grp.getgrnam.return_value = MagicMock(gr_gid=137)
        monkeypatch.setattr(
            abstracts.os,
            "fchown",
            MagicMock(side_effect=PermissionError("operation not permitted")),
        )
        machinery.dump_memory("win10_1", str(dump_file))
        assert (dump_file.stat().st_mode & 0o777) == 0o660
        assert vm.coreDump.call_count == 2

    def test_dump_memory_wraps_libvirt_error(self, tmp_path, monkeypatch):
        machinery, vm, _, DummyLibvirtError = self._make_machinery(monkeypatch)
        dump_file = tmp_path / "memory.dmp"
        vm.coreDump.side_effect = DummyLibvirtError("disk full")

        with pytest.raises(abstracts.CuckooMachineError, match="Error dumping memory virtual machine win10_1"):
            machinery.dump_memory("win10_1", str(dump_file))

