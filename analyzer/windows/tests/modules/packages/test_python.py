"""Tests for Windows Python 3.14+ runtime discovery, script execution, and Pillow version check."""

import ctypes
import importlib
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()
    ctypes.windll.ntdll.NtQueryInformationProcess.return_value = 0
os.environ.setdefault("SystemDrive", "C:")
os.environ.setdefault("TMP", "/tmp")

from lib.common.exceptions import CuckooPackageError
from modules.auxiliary import during_script as during_script_mod
from modules.auxiliary import pre_script as pre_script_mod
from modules.packages import python as python_pkg_mod


class TestWindowsPython314Runtime(unittest.TestCase):
    def test_python_package_discovers_pep773_pymanager_and_restores_pythonhome(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime_dir = os.path.join(tmpdir, "Python", "pythoncore-3.14-64")
            os.makedirs(os.path.join(runtime_dir, "Lib"), exist_ok=True)
            py_exe = os.path.join(runtime_dir, "python.exe")
            with open(py_exe, "wb") as fh:
                fh.write(b"MZ")
            sample = os.path.join(tmpdir, "sample.py")
            with open(sample, "w", encoding="utf-8") as fh:
                fh.write("print(1)\n")

            seen_pythonhome = []
            pkg = python_pkg_mod.Python(options={"arguments": "--test"})

            def fake_execute(exe, args, interest):
                seen_pythonhome.append(os.environ.get("PYTHONHOME"))
                return 4242

            with (
                patch.dict(os.environ, {"LocalAppData": tmpdir, "HomeDrive": "", "ProgramFiles": "", "SystemRoot": ""}, clear=False),
                patch.object(pkg, "execute", side_effect=fake_execute) as mock_exec,
            ):
                os.environ.pop("PYTHONHOME", None)
                pid = pkg.start(sample)

            self.assertEqual(pid, 4242)
            self.assertEqual(mock_exec.call_args[0][0], py_exe)
            self.assertEqual(seen_pythonhome, [runtime_dir])
            self.assertNotIn("PYTHONHOME", os.environ)

    def test_python_package_skips_pythonhome_for_py_launcher_and_falls_back_to_sys_executable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_launcher = os.path.join(tmpdir, "py.exe")
            with open(py_launcher, "wb") as fh:
                fh.write(b"MZ")
            sample = os.path.join(tmpdir, "sample.py")
            with open(sample, "w", encoding="utf-8") as fh:
                fh.write("print(1)\n")

            pkg = python_pkg_mod.Python(options={})
            seen_home = []

            def fake_execute(exe, args, interest):
                seen_home.append(os.environ.get("PYTHONHOME"))
                return 100

            with (
                patch.object(pkg, "get_path_glob", side_effect=[CuckooPackageError("no python"), py_launcher]),
                patch.object(pkg, "execute", side_effect=fake_execute),
            ):
                os.environ.pop("PYTHONHOME", None)
                self.assertEqual(pkg.start(sample), 100)
            self.assertEqual(seen_home, [None])

            with (
                patch.object(pkg, "get_path_glob", side_effect=CuckooPackageError("missing")),
                patch.object(pkg, "execute", return_value=200) as mock_exec,
            ):
                self.assertEqual(pkg.start(sample), 200)
            self.assertEqual(mock_exec.call_args[0][0], sys.executable)

    def test_pre_script_and_during_script_use_sys_executable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pre_path = os.path.join(tmpdir, "pre_script.py")
            during_path = os.path.join(tmpdir, "during_script.py")
            for p in (pre_path, during_path):
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("pass\n")

            fake_cfg = MagicMock(pre_script=True, during_script=True)
            with (
                patch.dict(os.environ, {"TEMP": tmpdir}),
                patch.object(pre_script_mod, "Config", return_value=fake_cfg),
                patch.object(during_script_mod, "Config", return_value=fake_cfg),
            ):
                pre = pre_script_mod.Pre_script(options={})
                during = during_script_mod.During_script(options={})

            self.assertEqual(pre.executable, [sys.executable])
            self.assertEqual(during.executable, [sys.executable, "-u"])

    def test_windows_screenshot_pillow_major_version_check(self):
        fake_pil = types.ModuleType("PIL")
        fake_pil.__version__ = "12.3.0"
        fake_pil.ImageDraw = types.ModuleType("PIL.ImageDraw")
        fake_pil.ImageGrab = types.ModuleType("PIL.ImageGrab")
        fake_chops = types.ModuleType("PIL.ImageChops")
        fake_chops.difference = lambda a, b: None

        modules_patch = {
            "PIL": fake_pil,
            "PIL.ImageChops": fake_chops,
            "PIL.ImageDraw": fake_pil.ImageDraw,
            "PIL.ImageGrab": fake_pil.ImageGrab,
        }
        try:
            with patch.dict(sys.modules, modules_patch):
                import lib.api.screenshot as screenshot_mod

                with self.assertNoLogs("lib.api.screenshot", level="INFO"):
                    importlib.reload(screenshot_mod)
                self.assertTrue(screenshot_mod.HAVE_PIL)

                fake_pil.__version__ = "4.3.0"
                with self.assertLogs("lib.api.screenshot", level="INFO") as logs:
                    importlib.reload(screenshot_mod)
                self.assertTrue(any("upgrade Pillow" in msg for msg in logs.output))
        finally:
            sys.modules.pop("lib.api.screenshot", None)
