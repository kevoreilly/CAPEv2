import logging
import os
import signal
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from modules.auxiliary import Mitmdump as mitmdump_mod


def _make_task(task_id=23, options="procmemdump=1,route=none"):
    return SimpleNamespace(id=task_id, options=options)


def _make_machine(ip="192.168.122.10"):
    return SimpleNamespace(ip=ip)


class TestMitmdumpOptions:
    @pytest.mark.parametrize(
        "options",
        [
            "procmemdump=1,route=none",
            "",
            None,
            "mitmdump=0",
            "mitmdump=no",
            "mitmdump=false",
            "mitmdump=",
            "nomitmdump=1",
            "referrer=https://example.com/mitmdump",
            "mitmdump=1,mitmdump=0",
        ],
    )
    def test_start_and_stop_skip_when_mitmdump_disabled(self, options, caplog):
        with patch.object(mitmdump_mod.Auxiliary, "__init__", return_value=None):
            aux = mitmdump_mod.Mitmdump()
        aux.set_task(_make_task(options=options))
        aux.set_machine(_make_machine())

        caplog.clear()
        with (
            patch.object(mitmdump_mod, "MitmdumpThread") as mock_thread_cls,
            patch.object(mitmdump_mod, "rooter") as mock_rooter,
            caplog.at_level(logging.ERROR),
        ):
            assert aux.start() is False
            aux.stop()

        mock_thread_cls.assert_not_called()
        mock_rooter.assert_not_called()
        assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []

    @pytest.mark.parametrize("options", ["mitmdump", "mitmdump=yes", "mitmdump=1", "MITMDUMP=1", "procmemdump=1, mitmdump=yes"])
    def test_start_launches_thread_when_mitmdump_enabled(self, options):
        with patch.object(mitmdump_mod.Auxiliary, "__init__", return_value=None):
            aux = mitmdump_mod.Mitmdump()
        aux.set_task(_make_task(options=options))
        aux.set_machine(_make_machine())

        fake_thread = MagicMock()
        with patch.object(mitmdump_mod, "MitmdumpThread", return_value=fake_thread) as mock_thread_cls:
            assert aux.start() is True
            aux.stop()

        mock_thread_cls.assert_called_once_with(aux.task, aux.machine)
        fake_thread.start.assert_called_once_with()
        fake_thread.stop.assert_called_once_with()

    @pytest.mark.parametrize("options", ["procmemdump=1,route=none", "", None, "mitmdump=0", "mitmdump=false"])
    def test_thread_stop_does_not_read_pid_or_disable_firewall_when_disabled(self, options, tmp_path, caplog):
        with (
            patch.object(mitmdump_mod, "CUCKOO_ROOT", str(tmp_path)),
            patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port") as mock_port,
        ):
            thread = mitmdump_mod.MitmdumpThread(_make_task(options=options), _make_machine())

        mock_port.assert_not_called()
        assert thread.host_port is None

        caplog.clear()
        with (
            patch.object(mitmdump_mod, "read_pid_from_file") as mock_read_pid,
            patch.object(mitmdump_mod, "rooter") as mock_rooter,
            caplog.at_level(logging.ERROR),
        ):
            thread.run()
            thread.stop()

        mock_read_pid.assert_not_called()
        mock_rooter.assert_not_called()
        assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []

    def test_get_netns_strips_whitespace(self, tmp_path):
        with (
            patch.object(mitmdump_mod, "CUCKOO_ROOT", str(tmp_path)),
            patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port", return_value="8001"),
        ):
            thread = mitmdump_mod.MitmdumpThread(_make_task(options="mitmdump=yes, netns=ns1 "), _make_machine())

        assert thread._get_netns() == "ns1"


class TestMitmdumpEnabled:
    def test_stop_skips_pid_and_disable_when_rooter_unavailable(self, tmp_path):
        with (
            patch.object(mitmdump_mod, "CUCKOO_ROOT", str(tmp_path)),
            patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port", return_value="8001"),
        ):
            thread = mitmdump_mod.MitmdumpThread(_make_task(options="mitmdump=yes"), _make_machine())

        with (
            patch.object(
                mitmdump_mod,
                "rooter",
                return_value={"output": None, "exception": "rooter is not reachable", "rooter_unavailable": True},
            ) as mock_rooter,
            patch.object(mitmdump_mod.subprocess, "Popen") as mock_popen,
            patch.object(mitmdump_mod, "read_pid_from_file") as mock_read_pid,
        ):
            thread.run()
            thread.stop()

        mock_popen.assert_not_called()
        mock_read_pid.assert_not_called()
        mock_rooter.assert_called_once_with("enable_mitmdump", thread.host_iface, "192.168.122.10", "8001", "")

    def test_enable_timeout_rolls_back_firewall_and_skips_popen(self, tmp_path):
        with (
            patch.object(mitmdump_mod, "CUCKOO_ROOT", str(tmp_path)),
            patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port", return_value="8001"),
        ):
            thread = mitmdump_mod.MitmdumpThread(_make_task(options="mitmdump=yes"), _make_machine())

        with (
            patch.object(mitmdump_mod, "rooter", return_value={"output": None, "exception": "timed out"}) as mock_rooter,
            patch.object(mitmdump_mod.subprocess, "Popen") as mock_popen,
            patch.object(mitmdump_mod, "read_pid_from_file") as mock_read_pid,
        ):
            thread.run()
            thread.stop()

        mock_popen.assert_not_called()
        mock_read_pid.assert_not_called()
        assert [c.args[0] for c in mock_rooter.call_args_list] == ["enable_mitmdump", "disable_mitmdump"]

    def test_popen_failure_rolls_back_firewall_once_and_skips_pid_read(self, tmp_path):
        with (
            patch.object(mitmdump_mod, "CUCKOO_ROOT", str(tmp_path)),
            patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port", return_value="8001"),
        ):
            thread = mitmdump_mod.MitmdumpThread(_make_task(options="mitmdump=yes"), _make_machine())

        with (
            patch.object(mitmdump_mod, "rooter", return_value={"output": "", "exception": None}) as mock_rooter,
            patch.object(mitmdump_mod.subprocess, "Popen", side_effect=OSError("missing binary")),
            patch.object(mitmdump_mod, "read_pid_from_file") as mock_read_pid,
        ):
            thread.run()
            thread.stop()

        mock_read_pid.assert_not_called()
        assert [c.args[0] for c in mock_rooter.call_args_list] == ["enable_mitmdump", "disable_mitmdump"]

    def test_stop_concurrent_with_enable_mitmdump_joins_skips_popen_and_disables(self, tmp_path):
        with (
            patch.object(mitmdump_mod, "CUCKOO_ROOT", str(tmp_path)),
            patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port", return_value="8001"),
        ):
            thread = mitmdump_mod.MitmdumpThread(_make_task(options="mitmdump=yes"), _make_machine())

        enable_entered = threading.Event()
        allow_enable_return = threading.Event()
        calls = []

        def fake_rooter(cmd, *args):
            calls.append(cmd)
            if cmd == "enable_mitmdump":
                enable_entered.set()
                assert allow_enable_return.wait(timeout=5)
            return {"output": "", "exception": None}

        with (
            patch.object(mitmdump_mod, "rooter", side_effect=fake_rooter),
            patch.object(mitmdump_mod.subprocess, "Popen") as mock_popen,
        ):
            thread.start()
            assert enable_entered.wait(timeout=5)

            stopper = threading.Thread(target=thread.stop)
            stopper.start()
            allow_enable_return.set()
            stopper.join(timeout=5)
            thread.join(timeout=5)

        mock_popen.assert_not_called()
        assert calls == ["enable_mitmdump", "disable_mitmdump"]

    def test_run_and_stop_reaps_direct_process_without_spinning(self, tmp_path):
        with (
            patch.object(mitmdump_mod, "CUCKOO_ROOT", str(tmp_path)),
            patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port", return_value="8001"),
        ):
            thread = mitmdump_mod.MitmdumpThread(_make_task(task_id=42, options="mitmdump=yes"), _make_machine("10.0.0.5"))

        os.makedirs(thread.mitmdump_path, exist_ok=True)
        with open(os.path.join(thread.mitmdump_path, "mitmdump.pid"), "w") as f:
            f.write("12345\n")

        fake_proc = MagicMock(pid=12345)
        fake_proc.poll.return_value = 0
        with (
            patch.object(mitmdump_mod, "rooter", return_value={"output": "", "exception": None}) as mock_rooter,
            patch.object(mitmdump_mod.subprocess, "Popen", return_value=fake_proc),
            patch.object(mitmdump_mod.os, "kill") as mock_kill,
            patch.object(mitmdump_mod, "wait_for_pid_exit") as mock_wait,
        ):
            thread.run()
            thread.stop()

        mock_kill.assert_called_once_with(12345, signal.SIGTERM)
        fake_proc.wait.assert_called_once_with(timeout=15)
        mock_wait.assert_not_called()
        assert [c.args for c in mock_rooter.call_args_list] == [
            ("enable_mitmdump", thread.host_iface, "10.0.0.5", "8001", ""),
            ("disable_mitmdump", thread.host_iface, "10.0.0.5", "8001", ""),
        ]

    @pytest.mark.parametrize("kill_exc", [ProcessLookupError(), PermissionError("operation not permitted")])
    def test_stop_still_disables_firewall_when_kill_fails_in_netns(self, tmp_path, kill_exc):
        with (
            patch.object(mitmdump_mod, "CUCKOO_ROOT", str(tmp_path)),
            patch.object(mitmdump_mod.MitmdumpThread, "_get_unused_port", return_value="8001"),
        ):
            thread = mitmdump_mod.MitmdumpThread(
                _make_task(task_id=43, options="mitmdump=yes,netns=ns1"),
                _make_machine("10.0.0.5"),
            )

        os.makedirs(thread.mitmdump_path, exist_ok=True)
        with open(os.path.join(thread.mitmdump_path, "mitmdump.pid"), "w") as f:
            f.write("99999\n")

        fake_proc = MagicMock(pid=12345)
        fake_proc.poll.return_value = 0
        with (
            patch.object(mitmdump_mod, "rooter", return_value={"output": "", "exception": None}) as mock_rooter,
            patch.object(mitmdump_mod.subprocess, "Popen", return_value=fake_proc),
            patch.object(mitmdump_mod.os, "kill", side_effect=kill_exc),
            patch.object(mitmdump_mod, "wait_for_pid_exit") as mock_wait,
        ):
            thread.run()
            thread.stop()

        mock_wait.assert_not_called()
        assert [c.args for c in mock_rooter.call_args_list] == [
            ("enable_mitmdump", thread.host_iface, "10.0.0.5", "8001", "ns1"),
            ("disable_mitmdump", thread.host_iface, "10.0.0.5", "8001", "ns1"),
        ]
