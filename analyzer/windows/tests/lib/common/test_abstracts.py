import ctypes
import importlib
import os
import unittest
from unittest.mock import MagicMock, patch

if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()
    ctypes.windll.ntdll.NtQueryInformationProcess.return_value = 0
os.environ.setdefault("SystemDrive", "C:")
os.environ.setdefault("TMP", "/tmp")

from lib.common import abstracts


class TestPackageConfiguration(unittest.TestCase):
    def test_private_package_configuration(self):
        # test analysis package
        package_module = self.__class__.__module__
        # and its private configuration module
        module_name = f"data.packages.{package_module}"

        class TestPackage(abstracts.Package):
            pass

        test_pkg = TestPackage(package_module)

        # private package configuration function with 2 args
        configure_called = False

        def configure(package, target):
            self.assertIs(package, test_pkg)
            self.assertEqual(target, self.id())
            nonlocal configure_called
            configure_called = True

        mock_module = MagicMock()
        mock_module.configure = configure

        with patch.object(importlib, "import_module", return_value=mock_module) as m:
            # do the private package configuration
            test_pkg.configure_from_data(self.id())
            # check it imported the private configuration module
            m.assert_called_once_with(module_name)
        self.assertTrue(configure_called)


class TestPackageExecuteMonitorHandle(unittest.TestCase):
    def tearDown(self):
        abstracts.Process.clear_monitor_handles()

    def test_execute_retains_monitor_handle_before_resume_when_not_free(self):
        events = []

        def fake_exit_code(h_proc, out_ptr):
            if h_proc == 0xCAFE:
                out_ptr._obj.value = 0xC0000135
                return 1
            return 0

        proc = abstracts.Process(options={}, config=MagicMock())
        orig_retain = proc.retain_monitor_handle

        def fake_execute(**_kwargs):
            proc.pid = 220
            proc.h_process = 0xAAA
            proc.h_thread = 0xBBB
            proc._cached_image_name = "sample.exe"
            return True

        def fake_retain():
            events.append("retain")
            return orig_retain()

        def fake_resume():
            events.append("resume")
            return True

        proc.execute = MagicMock(side_effect=fake_execute)
        proc.inject = MagicMock(return_value=True)
        proc.retain_monitor_handle = MagicMock(side_effect=fake_retain)
        proc.resume = MagicMock(side_effect=fake_resume)

        pkg = abstracts.Package(options={}, config=MagicMock())
        with (
            patch("lib.common.abstracts.Process", return_value=proc),
            patch("lib.api.process.KERNEL32") as mock_k32,
        ):
            mock_k32.OpenProcess.return_value = 0xCAFE
            mock_k32.CloseHandle.return_value = 1
            mock_k32.GetExitCodeProcess.side_effect = fake_exit_code

            pid = pkg.execute("C:\\Temp\\sample.exe", "", "C:\\Temp\\sample.exe")
            self.assertEqual(pid, 220)
            self.assertEqual(events, ["retain", "resume"])
            # Initial process handle and thread handle were closed by p.close(); PID was then reaped.
            mock_k32.OpenProcess.return_value = 0

            checker = abstracts.Process(pid=220)
            self.assertEqual(checker.exit_code(), 0xC0000135)
            self.assertEqual(checker.get_image_name(), "sample.exe")

    def test_execute_skips_monitor_handle_when_free(self):
        proc = MagicMock()
        proc.execute.return_value = True
        proc.pid = 221

        pkg = abstracts.Package(options={"free": True}, config=MagicMock())
        with patch("lib.common.abstracts.Process", return_value=proc):
            result = pkg.execute("C:\\Temp\\sample.exe", "", "C:\\Temp\\sample.exe")

        self.assertIsNone(result)
        proc.inject.assert_not_called()
        proc.retain_monitor_handle.assert_not_called()
        proc.resume.assert_called_once()
        proc.close.assert_called_once()
