import logging
import os
import signal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from modules.auxiliary import Mitmdump as mitmdump_mod


def _make_task(task_id=23, options="procmemdump=1,route=none"):
    return SimpleNamespace(id=task_id, options=options)


def _make_machine(ip="192.168.122.10"):
    return SimpleNamespace(ip=ip)


class TestMitmdumpDisabled:
    @pytest.mark.parametrize("options", ["procmemdump=1,route=none", "", None])
    def test_start_and_stop_skip_when_mitmdump_option_absent(self, options, caplog):
        with (
            patch.object(mitmdump_mod, "Database", create=True),
            patch.object(mitmdump_mod.Auxiliary, "__init__", return_value=None),
        ):
            aux = mitmdump_mod.Mitmdump()
        aux.set_task(_make_task(options=options))
        aux.set_machine(_make_machine())

        with (
            patch.object(mitmdump_mod, "MitmdumpThread") as mock_thread_cls,
            patch.object(mitmdump_mod, "rooter") as mock_rooter,
            caplog.at_level(logging.ERROR),
        ):
            assert aux.start() is False
            aux.stop()

        mock_thread_cls.assert_not_called()
        mock_rooter.assert_not_called()
        assert caplog.records == []

    @pytest.mark.parametrize("options", ["procmemdump=1,route=none", "", None])
    def test_thread_stop_does_not_read_pid_or_disable_firewall_when_disabled(self, options, caplog):
        with patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port") as mock_port:
            thread = mitmdump_mod.MitmdumpThread(_make_task(options=options), _make_machine())

        mock_port.assert_not_called()
        assert thread.host_port is None

        with patch.object(mitmdump_mod, "rooter") as mock_rooter, caplog.at_level(logging.ERROR):
            thread.run()
            thread.stop()

        mock_rooter.assert_not_called()
        assert caplog.records == []


class TestMitmdumpEnabled:
    def test_stop_skips_pid_read_and_firewall_disable_when_run_did_not_start_process(self, caplog):
        with patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port", return_value="8001"):
            thread = mitmdump_mod.MitmdumpThread(_make_task(options="mitmdump=yes"), _make_machine())

        with (
            patch.object(mitmdump_mod, "rooter", side_effect=mitmdump_mod.subprocess.CalledProcessError(1, "rooter")),
            patch.object(mitmdump_mod.subprocess, "Popen", side_effect=OSError("missing binary")),
            caplog.at_level(logging.ERROR),
        ):
            thread.run()

        caplog.clear()
        with (
            patch.object(mitmdump_mod, "read_pid_from_file") as mock_read_pid,
            patch.object(mitmdump_mod, "rooter") as mock_rooter,
            caplog.at_level(logging.ERROR),
        ):
            thread.stop()

        mock_read_pid.assert_not_called()
        mock_rooter.assert_not_called()
        assert caplog.records == []

    def test_run_and_stop_kill_pid_and_disable_firewall_when_enabled(self, tmp_path):
        with (
            patch.object(mitmdump_mod, "CUCKOO_ROOT", str(tmp_path)),
            patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port", return_value="8001"),
        ):
            thread = mitmdump_mod.MitmdumpThread(
                _make_task(task_id=42, options="mitmdump=yes,netns=ns1"),
                _make_machine("10.0.0.5"),
            )

        os.makedirs(thread.mitmdump_path, exist_ok=True)
        with open(os.path.join(thread.mitmdump_path, "mitmdump.pid"), "w") as f:
            f.write("99999\n")

        fake_proc = MagicMock(pid=12345)
        with (
            patch.object(mitmdump_mod, "rooter") as mock_rooter,
            patch.object(mitmdump_mod.subprocess, "Popen", return_value=fake_proc) as mock_popen,
            patch.object(mitmdump_mod.os, "kill") as mock_kill,
            patch.object(mitmdump_mod, "wait_for_pid_exit", return_value=True) as mock_wait,
        ):
            thread.run()
            thread.stop()

        mock_popen.assert_called_once()
        mock_kill.assert_called_once_with(99999, signal.SIGTERM)
        mock_wait.assert_called_once_with(99999, 15)
        assert mock_rooter.call_args_list[0].args == ("enable_mitmdump", thread.host_iface, "10.0.0.5", "8001", "ns1")
        assert mock_rooter.call_args_list[1].args == ("disable_mitmdump", thread.host_iface, "10.0.0.5", "8001", "ns1")
