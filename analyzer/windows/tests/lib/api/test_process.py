import os
import threading
import unittest
from unittest.mock import MagicMock, mock_open, patch

from lib.api.process import Process


class ProcessTests(unittest.TestCase):
    @patch("lib.api.process.LogServer")
    @patch("builtins.open", new_callable=mock_open)
    def test_monitor_config_advertises_loaded_process_identity(self, mocked_open, _mocked_logserver):
        process = Process(
            options={
                "loaded-process-identity": 0,
                "norefer": 1,
                "unsafe": "value\nloaded-process-identity=0",
                "eof": "value\x1aloaded-process-identity=0",
            },
            config=MagicMock(ip="192.0.2.1", port=2042),
            pid=4242,
        )
        old_process_num = Process.process_num
        try:
            Process.process_num = 0
            with patch.dict("lib.api.process.LOGSERVER_POOL", {}, clear=True):
                process.write_monitor_config(interest=r"C:\sample.exe")
        finally:
            Process.process_num = old_process_num

        config_text = "".join(call.args[0] for call in mocked_open().write.call_args_list)
        assert config_text.count("loaded-process-identity=1\n") == 1
        assert "loaded-process-identity=0\n" not in config_text
        assert "unsafe=" not in config_text
        assert "eof=" not in config_text
        assert config_text.endswith("loaded-process-identity=1\n")

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

    @patch("lib.api.process.nt_path_to_dos_path_ansi", return_value=r"C:\malware.exe")
    @patch("lib.api.process.os.path.exists", return_value=True)
    @patch("lib.api.process.subprocess.run")
    def test_inject_reports_loader_failure(self, mock_run, mock_exists, mock_nt_path):
        mock_run.return_value.returncode = 0
        process = Process(pid=4242)
        process.is_alive = MagicMock(return_value=True)
        process.is_64bit = MagicMock(return_value=True)
        process.write_monitor_config = MagicMock()
        process.get_filepath = MagicMock(return_value=r"C:\malware.exe")
        process.detect_dll_sideloading = MagicMock(return_value=False)

        assert process.inject() is False
