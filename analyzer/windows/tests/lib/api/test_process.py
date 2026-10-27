import os
import threading
import unittest
from unittest.mock import MagicMock, patch

from lib.api.process import Process


class ProcessTests(unittest.TestCase):
    @patch("lib.api.process.PSAPI", MagicMock(), create=True)
    def test_unknown_image_name(self):
        process = Process()
        assert f"{process}" == "<Process 0 ???>"

    def test_known_image_name(self):
        mock_image_name = MagicMock()
        mock_image_name.return_value = self.id()
        with patch("lib.api.process.Process.get_image_name", mock_image_name):
            process = Process()
            assert f"{process}" == f"<Process 0 {self.id()}>"

    def test_process_self(self):
        _ = Process(pid=os.getpid(), thread_id=threading.get_ident())

    def test_process_fill_system_info(self):
        p = Process()
        p.fill_system_info()
        # arbitrary sysinfo field assertion here
        self.assertNotEqual(0, p.system_info.dwPageSize)

    @patch("lib.api.process.create_custom_folders")
    @patch("lib.api.process.os.access", return_value=True)
    def test_execute_expands_env_vars_in_execution_directory(self, _mock_access, mock_create_folders):
        p = Process(options={"executiondir": "%UserProfile%\\Desktop"})
        with (
            patch.dict(os.environ, {"UserProfile": "C:\\Users\\Bruno"}, clear=False),
            patch.object(p, "build_parent_attribute_list", return_value=(None, MagicMock(), None)),
            patch("lib.api.process.KERNEL32") as mock_k32,
        ):
            mock_k32.CreateProcessW.return_value = True
            self.assertTrue(p.execute("C:\\Users\\Bruno\\Desktop\\sample.exe"))
            expected_dir = os.path.expandvars("%UserProfile%\\Desktop")
            mock_create_folders.assert_called_once_with(expected_dir)
            self.assertEqual(mock_k32.CreateProcessW.call_args[0][7], expected_dir)

    @patch("lib.api.process.get_error_string", return_value="The requested operation requires elevation.")
    @patch("lib.api.process.create_custom_folders")
    @patch("lib.api.process.os.access", return_value=True)
    def test_execute_fallback_when_parent_spoofing_fails(self, _mock_access, _mock_create_folders, _mock_err_str):
        from lib.common.defines import CREATE_NEW_CONSOLE, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT

        p = Process(options={"executiondir": "C:\\Users\\Bruno\\Desktop"})
        with (
            patch.object(p, "build_parent_attribute_list", return_value=(None, MagicMock(), None)),
            patch("lib.api.process.KERNEL32") as mock_k32,
        ):
            mock_k32.CreateProcessW.side_effect = [False, True]
            mock_k32.GetLastError.return_value = 740
            self.assertTrue(p.execute("C:\\Users\\Bruno\\Desktop\\installer.exe"))
            self.assertEqual(mock_k32.CreateProcessW.call_count, 2)
            first_flags = mock_k32.CreateProcessW.call_args_list[0][0][5]
            second_flags = mock_k32.CreateProcessW.call_args_list[1][0][5]
            self.assertEqual(first_flags, CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED)
            self.assertEqual(second_flags, CREATE_NEW_CONSOLE | CREATE_SUSPENDED)

    @patch("lib.api.process.get_error_string", return_value="Access is denied.")
    @patch("lib.api.process.create_custom_folders")
    @patch("lib.api.process.os.access", return_value=True)
    def test_execute_returns_false_when_both_attempts_fail(self, _mock_access, _mock_create_folders, _mock_err_str):
        p = Process(options={"executiondir": "C:\\Users\\Bruno\\Desktop"})
        with (
            patch.object(p, "build_parent_attribute_list", return_value=(None, MagicMock(), None)),
            patch("lib.api.process.KERNEL32") as mock_k32,
        ):
            mock_k32.CreateProcessW.side_effect = [False, False]
            mock_k32.GetLastError.return_value = 5
            self.assertFalse(p.execute("C:\\Users\\Bruno\\Desktop\\installer.exe"))
            self.assertEqual(mock_k32.CreateProcessW.call_count, 2)
