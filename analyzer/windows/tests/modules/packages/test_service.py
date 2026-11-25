"""Tests for Service and ServiceDll packages on 64-bit Python."""

import ctypes
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()
    ctypes.windll.ntdll.NtQueryInformationProcess.return_value = 0
if not hasattr(ctypes, "FormatError"):
    ctypes.FormatError = lambda *args, **kwargs: "mock error"
os.environ.setdefault("SystemDrive", "C:")
os.environ.setdefault("TMP", "/tmp")

if "winreg" not in sys.modules:
    _fake_winreg = types.ModuleType("winreg")
    _fake_winreg.HKEY_LOCAL_MACHINE = 0x80000002
    _fake_winreg.KEY_ALL_ACCESS = 0xF003F
    _fake_winreg.KEY_WOW64_64KEY = 0x0100
    _fake_winreg.REG_EXPAND_SZ = 2
    _fake_winreg.REG_MULTI_SZ = 7
    _fake_winreg.CreateKeyEx = MagicMock()
    _fake_winreg.DeleteValue = MagicMock()
    _fake_winreg.OpenKeyEx = MagicMock()
    _fake_winreg.SetValueEx = MagicMock()
    sys.modules["winreg"] = _fake_winreg

from modules.packages import service as service_mod
from modules.packages import service_dll as service_dll_mod


class TestServicePackagesWin64(unittest.TestCase):
    def test_service_handles_null_none_and_bytes_arguments(self):
        cfg = MagicMock(services_pid=999)
        pkg = service_mod.Service(options={"arguments": "--flag value"}, config=cfg)

        with (
            patch.object(service_mod, "check_file_extension", return_value=r"C:\Temp\svc.exe"),
            patch.object(service_mod, "ADVAPI32") as advapi,
        ):
            # OpenSCManagerA returns None (NULL HANDLE) on 64-bit ctypes.
            advapi.OpenSCManagerA.return_value = None
            pkg.start(r"C:\Temp\svc.exe")
            advapi.CreateServiceA.assert_not_called()

            # CreateServiceA returning None closes scm_handle and encodes arguments as bytes.
            advapi.OpenSCManagerA.return_value = 0x1000
            advapi.CreateServiceA.return_value = None
            pkg.start(r"C:\Temp\svc.exe")
            self.assertEqual(advapi.CreateServiceA.call_args[0][7], b'"C:\\Temp\\svc.exe" --flag value')
            advapi.CloseServiceHandle.assert_called_once_with(0x1000)

    def test_service_dll_set_keys_continues_when_wow64_value_missing(self):
        pkg = service_dll_mod.ServiceDll(options={}, config=MagicMock())
        key_cm = MagicMock()
        key_cm.__enter__.return_value = key_cm

        with (
            patch.object(service_dll_mod, "CreateKeyEx", return_value=key_cm),
            patch.object(service_dll_mod, "OpenKeyEx", return_value=key_cm),
            patch.object(service_dll_mod, "DeleteValue", side_effect=FileNotFoundError("WOW64 not present")),
            patch.object(service_dll_mod, "SetValueEx") as mock_set_val,
        ):
            pkg.set_keys("CAPEService", r"C:\Temp\sample.dll")

        set_names = [call[0][1] for call in mock_set_val.call_args_list]
        self.assertEqual(set_names, ["ServiceDll", "capegroup"])

    def test_service_dll_handles_blank_name_and_null_service_handle(self):
        pkg = service_dll_mod.ServiceDll(options={"servicename": "blank"}, config=MagicMock(services_pid=999))
        with (
            patch.object(service_dll_mod, "check_file_extension", return_value=r"C:\Temp\svc.dll"),
            patch.object(service_dll_mod, "ADVAPI32") as advapi,
        ):
            advapi.OpenSCManagerA.return_value = 0x2000
            advapi.CreateServiceA.return_value = None
            pkg.start(r"C:\Temp\svc.dll")

        self.assertEqual(advapi.CreateServiceA.call_args[0][1], b" ")
        advapi.CloseServiceHandle.assert_called_once_with(0x2000)
