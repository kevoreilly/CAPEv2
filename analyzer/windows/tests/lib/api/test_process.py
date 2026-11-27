import ctypes
import logging
import os
import subprocess
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch

if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()
    ctypes.windll.ntdll.NtQueryInformationProcess.return_value = 0
os.environ.setdefault("SystemDrive", "C:")
os.environ.setdefault("TMP", "/tmp")

from lib.api.process import Process
from lib.common.errors import format_ntstatus


class _FormattingListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append((record.levelno, self.format(record)))


class ProcessTests(unittest.TestCase):
    def tearDown(self):
        Process.clear_monitor_handles()
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

    def test_monitor_handle_retains_exit_code_and_image_name_after_close_and_reap(self):
        def fill_image_name(h_proc, buf, size):
            if h_proc == 0xCAFE:
                buf.value = b"\\Device\\HarddiskVolume1\\sample.exe"
                return len(buf.value)
            return 0

        def fill_exit_code(h_proc, out_ptr):
            if h_proc == 0xCAFE:
                out_ptr._obj.value = 0xC0000135
                return 1
            return 0

        with patch("lib.api.process.KERNEL32") as mock_k32, patch("lib.api.process.PSAPI") as mock_psapi:
            mock_k32.OpenProcess.return_value = 0xCAFE
            mock_k32.CloseHandle.return_value = 1
            mock_psapi.GetProcessImageFileNameA.side_effect = fill_image_name
            mock_k32.GetExitCodeProcess.side_effect = fill_exit_code

            proc = Process(pid=220, h_process=0xAAA, h_thread=0xBBB)
            self.assertTrue(proc.retain_monitor_handle())
            self.assertTrue(proc.close())
            # close() only closed h_process and h_thread, leaving the monitor handle open.
            closed_handles = [getattr(c[0][0], "value", c[0][0]) for c in mock_k32.CloseHandle.call_args_list]
            self.assertEqual(closed_handles, [0xAAA, 0xBBB])

            # Subsequent OpenProcess calls fail because the OS has reaped the exited PID.
            mock_k32.OpenProcess.return_value = 0
            mock_k32.CloseHandle.reset_mock()

            checker = Process(pid=220)
            with self.assertNoLogs("lib.api.process", level="WARNING"):
                self.assertEqual(checker.exit_code(), 0xC0000135)
                self.assertEqual(checker.get_image_name(), "sample.exe")

            Process.release_monitor_handle(220)
            mock_k32.CloseHandle.assert_called_once_with(0xCAFE)
            self.assertNotIn(220, Process._monitor_handles)

    def test_monitor_handle_lock_held_across_queries_and_close(self):
        lock_states = []

        def check_exit_code(h_proc, out_ptr):
            lock_states.append(("GetExitCodeProcess", Process._monitor_handles_lock.locked()))
            out_ptr._obj.value = 0
            return 1

        def check_image_name(h_proc, buf, size):
            lock_states.append(("GetProcessImageFileNameA", Process._monitor_handles_lock.locked()))
            buf.value = b"\\Device\\HarddiskVolume1\\locked.exe"
            return len(buf.value)

        def check_close(h_proc):
            lock_states.append(("CloseHandle", Process._monitor_handles_lock.locked()))
            return 1

        with patch("lib.api.process.KERNEL32") as mock_k32, patch("lib.api.process.PSAPI") as mock_psapi:
            mock_k32.GetExitCodeProcess.side_effect = check_exit_code
            mock_psapi.GetProcessImageFileNameA.side_effect = check_image_name
            mock_k32.CloseHandle.side_effect = check_close

            # Seed retained monitor handle without cached image name so both exit_code() and get_image_name() query it.
            with Process._monitor_handles_lock:
                Process._monitor_handles[555] = (0xBEEF, "")
            checker = Process(pid=555)
            self.assertEqual(checker.exit_code(), 0)
            self.assertEqual(checker.get_image_name(), "locked.exe")
            Process.release_monitor_handle(555)

        self.assertEqual(
            lock_states,
            [
                ("GetExitCodeProcess", True),
                ("GetProcessImageFileNameA", True),
                ("CloseHandle", True),
            ],
        )

    def test_exit_code_monitor_failure_debug_log_does_not_deadlock(self):
        proc_logger = logging.getLogger("lib.api.process")
        orig_handlers = list(proc_logger.handlers)
        orig_level = proc_logger.level
        orig_propagate = proc_logger.propagate
        handler = _FormattingListHandler()

        try:
            proc_logger.handlers = [handler]
            proc_logger.setLevel(logging.DEBUG)
            proc_logger.propagate = False

            def fill_image_name(_h_proc, buf, _size):
                buf.value = b"\\Device\\HarddiskVolume1\\deadlock_check.exe"
                return len(buf.value)

            with patch("lib.api.process.KERNEL32") as mock_k32, patch("lib.api.process.PSAPI") as mock_psapi:
                mock_k32.GetExitCodeProcess.return_value = 0
                mock_psapi.GetProcessImageFileNameA.side_effect = fill_image_name
                with Process._monitor_handles_lock:
                    Process._monitor_handles[556] = (0xBEEF, "")

                checker = Process(pid=556)
                result = []
                worker = threading.Thread(target=lambda: result.append(checker.exit_code()), daemon=True)
                worker.start()
                worker.join(timeout=2.0)
                self.assertFalse(worker.is_alive(), "exit_code() deadlocked while formatting debug log")
                self.assertEqual(result, [None])
                self.assertTrue(any("deadlock_check.exe" in msg for _, msg in handler.messages))
        finally:
            proc_logger.handlers = orig_handlers
            proc_logger.setLevel(orig_level)
            proc_logger.propagate = orig_propagate

    def test_resume_handles_unsigned_dword_failure(self):
        with patch("lib.api.process.KERNEL32") as mock_k32:
            mock_k32.ResumeThread.return_value = 0xFFFFFFFF
            proc = Process(pid=777, h_thread=0x444)
            self.assertFalse(proc.resume())

            mock_k32.ResumeThread.return_value = 1
            self.assertTrue(proc.resume())

    def test_retain_pid_monitor_handle_preserves_existing_handle_and_is_silent_on_failure(self):
        with patch("lib.api.process.KERNEL32") as mock_k32, patch("lib.api.process.PSAPI"):
            mock_k32.OpenProcess.return_value = 0x1111
            self.assertTrue(Process.retain_pid_monitor_handle(333))
            self.assertEqual(mock_k32.OpenProcess.call_count, 1)

            # Second call keeps the existing valid handle and fills in the missing image name.
            self.assertTrue(Process.retain_pid_monitor_handle(333, "worker.exe"))
            self.assertEqual(mock_k32.OpenProcess.call_count, 1)
            self.assertEqual(Process._monitor_handles[333], (0x1111, "worker.exe"))

            # Failures during silent monitor retention must not emit warning logs.
            mock_k32.OpenProcess.return_value = 0
            with self.assertNoLogs("lib.api.process", level="WARNING"):
                self.assertFalse(Process.retain_pid_monitor_handle(444))
            self.assertNotIn(444, Process._monitor_handles)

    def test_open_failed_suppresses_retries_and_untracked_dual_handler_logging(self):
        proc_logger = logging.getLogger("lib.api.process")
        orig_handlers = list(proc_logger.handlers)
        orig_level = proc_logger.level
        orig_propagate = proc_logger.propagate
        h1 = _FormattingListHandler()
        h2 = _FormattingListHandler()

        try:
            proc_logger.handlers = [h1, h2]
            proc_logger.setLevel(logging.DEBUG)
            proc_logger.propagate = False

            with patch("lib.api.process.KERNEL32") as mock_k32, patch("lib.api.process.PSAPI") as mock_psapi:
                mock_k32.OpenProcess.return_value = 0

                p = Process(pid=555)
                self.assertIsNone(p.exit_code())
                first_open_attempts = mock_k32.OpenProcess.call_count
                self.assertEqual(first_open_attempts, 2)

                # Subsequent calls must not retry OpenProcess or pass None to PSAPI.
                self.assertEqual(p.get_image_name(), "")
                self.assertFalse(p.open())
                self.assertEqual(mock_k32.OpenProcess.call_count, first_open_attempts)
                mock_psapi.GetProcessImageFileNameA.assert_not_called()

            msgs1 = [msg for _, msg in h1.messages]
            msgs2 = [msg for _, msg in h2.messages]
            self.assertEqual(msgs1, msgs2)
            self.assertEqual(sum(1 for m in msgs1 if "failed to open process 555" in m), 1)
            self.assertEqual(sum(1 for m in msgs1 if "Failed getting image name" in m), 0)
            self.assertEqual(sum(1 for m in msgs1 if "Failed getting exit code for <Process 555 ???>" in m), 1)
        finally:
            proc_logger.handlers = orig_handlers
            proc_logger.setLevel(orig_level)
            proc_logger.propagate = orig_propagate

    def test_execute_caches_image_name_and_resets_open_failed(self):
        p = Process()
        p._open_failed = True
        with (
            patch("lib.api.process.os.access", return_value=True),
            patch("lib.api.process.create_custom_folders"),
            patch.object(p, "build_parent_attribute_list", return_value=(None, MagicMock(), None)),
            patch("lib.api.process.KERNEL32") as mock_k32,
        ):
            mock_k32.CreateProcessW.return_value = True
            self.assertTrue(p.execute("C:\\Temp\\payload.exe"))

        self.assertFalse(p._open_failed)
        self.assertEqual(p._cached_image_name, "payload.exe")
        self.assertEqual(p.get_image_name(), "payload.exe")

    def test_format_ntstatus(self):
        self.assertEqual(format_ntstatus(0xC0000135), "STATUS_DLL_NOT_FOUND")
        self.assertEqual(format_ntstatus(-1073741515), "STATUS_DLL_NOT_FOUND")
        self.assertIsNone(format_ntstatus(0))

    def test_del_ignores_null_current_process_and_mock_handles(self):
        closed = []
        c_close = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)(lambda h: closed.append(h) or 1)
        with patch("lib.api.process.KERNEL32") as mock_k32:
            mock_k32.GetCurrentProcess.return_value = -1
            mock_k32.CloseHandle = c_close

            p_mock = Process()
            p_mock.h_process = MagicMock()
            p_mock.h_thread = MagicMock()
            p_mock.__del__()

            p_self = Process()
            p_self.h_process = -1
            p_self.h_thread = 0
            p_self.__del__()

            p_real = Process(h_process=0x1234, h_thread=0x5678)
            p_real.__del__()
            p_real.h_process = None
            p_real.h_thread = None

        self.assertEqual(closed, [0x1234, 0x5678])

    def test_kernel_analyze_win64_skips_wow64_and_encodes_ioctls(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            dll_dir = os.path.join(tmpdir, "dll")
            os.makedirs(dll_dir, exist_ok=True)
            for fname in ("zer0m0n_x64.sys", "logs_dispatcher.exe"):
                with open(os.path.join(dll_dir, fname), "wb") as fh:
                    fh.write(b"MZ")

            proc = Process(pid=1234)
            fake_cfg = MagicMock(ip="192.168.56.1", port=2042)
            orig_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                with (
                    patch("lib.api.process.is_os_64bit", return_value=True),
                    patch("lib.api.process.sys.maxsize", 2**63 - 1),
                    patch("lib.api.process.os.system"),
                    patch("lib.api.process.Config", return_value=fake_cfg),
                    patch.object(Process, "get_parent_pid", return_value=42),
                    patch.dict(os.environ, {"TEMP": tmpdir}),
                    patch("lib.api.process.KERNEL32") as mock_k32,
                ):
                    mock_k32.CreateProcessW.return_value = True
                    mock_k32.CreateFileW.return_value = 0x5555
                    mock_k32.CreateToolhelp32Snapshot.return_value = 0x6666
                    mock_k32.Process32First.return_value = False

                    self.assertTrue(proc.kernel_analyze())

                mock_k32.Wow64DisableWow64FsRedirection.assert_not_called()
                mock_k32.Wow64RevertWow64FsRedirection.assert_not_called()
                self.assertIs(mock_k32.CreateProcessW.call_args[0][4], False)
                self.assertEqual(mock_k32.DeviceIoControl.call_count, 2)
                for call in mock_k32.DeviceIoControl.call_args_list:
                    self.assertIsInstance(call[0][2], bytes)
                closed = [call[0][0] for call in mock_k32.CloseHandle.call_args_list]
                self.assertIn(0x6666, closed)
                self.assertIn(0x5555, closed)
            finally:
                os.chdir(orig_cwd)

    def _write_unicode_string_into_buf(self, buf_ptr, text: str) -> int:
        from lib.api.process import _UNICODE_STRING_PTR

        encoded = text.encode("utf-16le")
        hdr_size = ctypes.sizeof(_UNICODE_STRING_PTR)
        buf_addr = ctypes.addressof(buf_ptr._obj)
        us = _UNICODE_STRING_PTR(
            Length=len(encoded),
            MaximumLength=len(encoded) + 2,
            Buffer=buf_addr + hdr_size,
        )
        ctypes.memmove(buf_addr, ctypes.byref(us), hdr_size)
        ctypes.memmove(buf_addr + hdr_size, encoded, len(encoded))
        return hdr_size + len(encoded) + 2

    def test_get_command_line_parses_unicode_string(self):
        from lib.api.process import PROCESS_COMMAND_LINE_INFORMATION

        expected = r"C:\Windows\system32\DllHost.exe /Processid:{49F171DD-B51A-40D3-9A6C-52D674CC729D}"

        def fake_ntquery(h_proc, info_class, buf_ptr, buf_len, ret_len_ptr):
            self.assertEqual(info_class, PROCESS_COMMAND_LINE_INFORMATION)
            written = self._write_unicode_string_into_buf(buf_ptr, expected)
            ret_len_ptr._obj.value = written
            return 0

        with patch("lib.api.process.NTDLL") as mock_ntdll, patch("lib.api.process.KERNEL32"):
            mock_ntdll.NtQueryInformationProcess.side_effect = fake_ntquery
            proc = Process(pid=3872, h_process=0x1234)
            try:
                self.assertEqual(proc.get_command_line(), expected)
            finally:
                proc.h_process = None

    def test_get_command_line_retries_on_info_length_mismatch(self):
        from lib.api.process import _UNICODE_STRING_PTR

        expected = "C:\\Windows\\system32\\DllHost.exe " + ("A" * 3000)
        needed = ctypes.sizeof(_UNICODE_STRING_PTR) + len(expected.encode("utf-16le")) + 2
        calls = []

        def fake_ntquery(h_proc, info_class, buf_ptr, buf_len, ret_len_ptr):
            calls.append(buf_len)
            if buf_len < needed:
                ret_len_ptr._obj.value = needed
                return -1073741820  # STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
            written = self._write_unicode_string_into_buf(buf_ptr, expected)
            ret_len_ptr._obj.value = written
            return 0

        with patch("lib.api.process.NTDLL") as mock_ntdll, patch("lib.api.process.KERNEL32"):
            mock_ntdll.NtQueryInformationProcess.side_effect = fake_ntquery
            proc = Process(pid=3872, h_process=0x1234)
            try:
                self.assertEqual(proc.get_command_line(), expected)
            finally:
                proc.h_process = None

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], needed)

    def test_get_command_line_returns_empty_on_unsupported_info_class(self):
        with patch("lib.api.process.NTDLL") as mock_ntdll, patch("lib.api.process.KERNEL32"):
            mock_ntdll.NtQueryInformationProcess.return_value = -1073741821  # STATUS_INVALID_INFO_CLASS
            proc = Process(pid=3872, h_process=0x1234)
            try:
                self.assertEqual(proc.get_command_line(), "")
            finally:
                proc.h_process = None

    def test_get_command_line_returns_empty_when_open_fails(self):
        with patch("lib.api.process.NTDLL") as mock_ntdll, patch("lib.api.process.KERNEL32") as mock_k32:
            mock_k32.OpenProcess.return_value = 0
            proc = Process(pid=9999)
            self.assertEqual(proc.get_command_line(), "")
            mock_ntdll.NtQueryInformationProcess.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "Requires native Windows NtQueryInformationProcess")
    def test_get_command_line_live_current_process(self):
        proc = Process(pid=os.getpid())
        try:
            cmdline = proc.get_command_line()
        finally:
            proc.close()
        self.assertTrue(cmdline)
        self.assertIn("python", cmdline.lower())

    @unittest.skipUnless(sys.platform == "win32", "Requires native Windows NtQueryInformationProcess")
    def test_get_command_line_and_parent_pid_live_cross_bitness(self):
        from lib.api.process import is_os_64bit

        if not is_os_64bit():
            self.skipTest("Cross-bitness test requires 64-bit Windows")

        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        if sys.maxsize > 2**32:
            target_exe = os.path.join(system_root, "SysWOW64", "cmd.exe")
            expect_64bit = False
        else:
            target_exe = os.path.join(system_root, "Sysnative", "cmd.exe")
            expect_64bit = True

        if not os.path.isfile(target_exe):
            self.skipTest(f"Opposite-bitness cmd.exe not found at {target_exe}")

        marker = "CAPEV2_CROSS_BITNESS_CMDLINE_CHECK"
        child = subprocess.Popen(
            [target_exe, "/k", f"rem {marker}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc = Process(pid=child.pid)
        try:
            self.assertEqual(proc.is_64bit(), expect_64bit)
            self.assertIn(marker, proc.get_command_line())
            self.assertEqual(proc.get_parent_pid(), os.getpid())
            self.assertTrue(proc.get_filepath().lower().endswith("\\cmd.exe"))
        finally:
            proc.close()
            if child.stdin:
                child.stdin.close()
            child.terminate()
            child.wait(timeout=5)
