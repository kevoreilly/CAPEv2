import errno
import fcntl
import logging
import os
import sys
import types
from unittest.mock import MagicMock

import pytest

import cuckoo as cuckoo_mod
from lib.cuckoo.common.dictionary import Dictionary
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooStartupError
from lib.cuckoo.common.utils import Singleton
import lib.cuckoo.core.resultserver as rs_mod


class _FakeSocket:
    def __init__(self, bind_behaviors, listen_error=None):
        self._bind_behaviors = bind_behaviors
        self._listen_error = listen_error
        self.closed = False
        self.bound_addr = None
        self.listened = False
        self.options = []

    def setsockopt(self, level, optname, value):
        self.options.append((level, optname, value))

    def bind(self, addr):
        action = self._bind_behaviors.pop(0) if self._bind_behaviors else None
        if isinstance(action, BaseException):
            raise action
        self.bound_addr = addr

    def getsockname(self):
        return self.bound_addr

    def listen(self, backlog):
        if self._listen_error is not None:
            raise self._listen_error
        self.listened = True

    def close(self):
        self.closed = True


def _make_cfg(**overrides):
    rs_cfg = Dictionary(
        {
            "ip": "192.168.1.1",
            "port": 2042,
            "pool_size": 0,
            "force_port": True,
            "multiworker": False,
            "base_port": 2042,
            "bind_retries": 2,
            "bind_retry_delay": 0.1,
        }
    )
    rs_cfg.update(overrides)
    return Dictionary({"resultserver": rs_cfg})


def test_legacy_bind_retries_and_succeeds_after_transient_eaddrinuse(monkeypatch):
    created_sockets = []
    bind_plan = [
        OSError(errno.EADDRINUSE, "Address already in use"),
        OSError(errno.EADDRINUSE, "Address already in use"),
        None,
    ]
    sleeps = []

    def fake_socket(*_args, **_kwargs):
        s = _FakeSocket(bind_plan)
        created_sockets.append(s)
        return s

    monkeypatch.setattr(rs_mod, "cfg", _make_cfg(bind_retries=3, bind_retry_delay=0.25))
    monkeypatch.setattr(rs_mod, "categories_need_VM", True)
    monkeypatch.setattr(rs_mod.gevent.socket, "socket", fake_socket)
    monkeypatch.setattr(rs_mod.time, "sleep", sleeps.append)
    monkeypatch.setattr(rs_mod, "Thread", lambda target, args: MagicMock())
    Singleton._instances.pop(rs_mod.ResultServer, None)

    try:
        server = rs_mod.ResultServer()
        assert server.port == 2042
        assert len(created_sockets) == 3
        assert created_sockets[0].closed is True
        assert created_sockets[1].closed is True
        assert created_sockets[2].closed is False
        assert created_sockets[2].listened is True
        assert sleeps == [0.25, 0.25]
    finally:
        rs_mod.ResultServer.shutdown_if_running()


def test_legacy_bind_eaddrinuse_raises_clean_startup_error_with_holder(monkeypatch):
    created_sockets = []
    bind_plan = [
        OSError(errno.EADDRINUSE, "Address already in use"),
        OSError(errno.EADDRINUSE, "Address already in use"),
    ]

    def fake_socket(*_args, **_kwargs):
        s = _FakeSocket(bind_plan)
        created_sockets.append(s)
        return s

    monkeypatch.setattr(rs_mod, "cfg", _make_cfg(bind_retries=1, bind_retry_delay=0.05))
    monkeypatch.setattr(rs_mod, "categories_need_VM", True)
    monkeypatch.setattr(rs_mod.gevent.socket, "socket", fake_socket)
    monkeypatch.setattr(rs_mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(rs_mod, "_describe_port_holder", lambda ip, port: "PID 4242 (python: python cuckoo.py)")
    Singleton._instances.pop(rs_mod.ResultServer, None)

    with pytest.raises(CuckooStartupError) as exc_info:
        rs_mod.ResultServer()

    err = exc_info.value
    msg = str(err)
    assert isinstance(err, CuckooCriticalError)
    assert err.__suppress_context__ is True
    assert "192.168.1.1:2042" in msg
    assert "PID 4242 (python: python cuckoo.py)" in msg
    assert "sudo systemctl stop cape.service" in msg
    assert "bailingThis" not in msg
    assert "run the just use" not in msg
    assert all(s.closed for s in created_sockets)
    assert rs_mod.ResultServer not in Singleton._instances


def test_legacy_bind_force_port_false_increments_port(monkeypatch):
    created_sockets = []
    bind_plan = [
        OSError(errno.EADDRINUSE, "Address already in use"),
        None,
    ]

    def fake_socket(*_args, **_kwargs):
        s = _FakeSocket(bind_plan)
        created_sockets.append(s)
        return s

    monkeypatch.setattr(rs_mod, "cfg", _make_cfg(force_port=False, bind_retries=2))
    monkeypatch.setattr(rs_mod, "categories_need_VM", True)
    monkeypatch.setattr(rs_mod.gevent.socket, "socket", fake_socket)
    monkeypatch.setattr(rs_mod, "Thread", lambda target, args: MagicMock())
    Singleton._instances.pop(rs_mod.ResultServer, None)

    try:
        server = rs_mod.ResultServer()
        assert server.port == 2043
        assert created_sockets[0].closed is True
        assert created_sockets[1].bound_addr == ("192.168.1.1", 2043)
    finally:
        rs_mod.ResultServer.shutdown_if_running()


def test_legacy_bind_eaddrnotavail_raises_clean_startup_error_and_closes_socket(monkeypatch):
    created_sockets = []
    bind_plan = [OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")]

    def fake_socket(*_args, **_kwargs):
        s = _FakeSocket(bind_plan)
        created_sockets.append(s)
        return s

    monkeypatch.setattr(rs_mod, "cfg", _make_cfg(bind_retries=2))
    monkeypatch.setattr(rs_mod, "categories_need_VM", True)
    monkeypatch.setattr(rs_mod.gevent.socket, "socket", fake_socket)
    Singleton._instances.pop(rs_mod.ResultServer, None)

    with pytest.raises(CuckooStartupError) as exc_info:
        rs_mod.ResultServer()

    msg = str(exc_info.value)
    assert "192.168.1.1:2042" in msg
    assert "informationOne" not in msg
    assert "cuckoo.conf.Make" not in msg
    assert created_sockets[0].closed is True


def test_resultserver_shutdown_if_running_closes_legacy_socket_and_clears_singleton(monkeypatch):
    sock = _FakeSocket([None])
    monkeypatch.setattr(rs_mod, "cfg", _make_cfg())
    monkeypatch.setattr(rs_mod, "categories_need_VM", True)
    monkeypatch.setattr(rs_mod.gevent.socket, "socket", lambda *_a, **_kw: sock)
    monkeypatch.setattr(rs_mod, "Thread", lambda target, args: MagicMock())
    Singleton._instances.pop(rs_mod.ResultServer, None)

    server = rs_mod.ResultServer()
    fake_instance = MagicMock()
    server.instance = fake_instance

    rs_mod.ResultServer.shutdown_if_running()
    fake_instance.stop.assert_called_once_with(timeout=2)
    assert sock.closed is True
    assert rs_mod.ResultServer not in Singleton._instances
    # Second call is a safe no-op
    rs_mod.ResultServer.shutdown_if_running()


def test_describe_port_holder_matches_listening_socket(monkeypatch):
    fake_conn = types.SimpleNamespace(
        status="LISTEN",
        laddr=types.SimpleNamespace(ip="0.0.0.0", port=2042),
        pid=os.getpid() + 100,
    )

    class _FakeProc:
        def __init__(self, pid):
            self.pid = pid

        def name(self):
            return "python"

        def cmdline(self):
            return ["/opt/CAPEv2/.venv/bin/python", "cuckoo.py"]

    fake_psutil = types.SimpleNamespace(
        CONN_LISTEN="LISTEN",
        net_connections=lambda kind="inet": [fake_conn],
        Process=_FakeProc,
    )
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)

    holder = rs_mod._describe_port_holder("192.168.1.1", 2042)
    assert holder == f"PID {os.getpid() + 100} (python: /opt/CAPEv2/.venv/bin/python cuckoo.py)"


def test_cuckoo_instance_lock_blocks_second_instance_and_releases(tmp_path):
    cuckoo_mod._release_cuckoo_lock()
    lock_file = cuckoo_mod._acquire_cuckoo_lock(str(tmp_path))
    assert lock_file is not None
    try:
        # Simulate a second process trying to acquire the same lock
        cuckoo_mod._CUCKOO_LOCK_FD = None
        with pytest.raises(CuckooStartupError) as exc_info:
            cuckoo_mod._acquire_cuckoo_lock(str(tmp_path))
        msg = str(exc_info.value)
        assert f"PID {os.getpid()}" in msg
        assert "sudo systemctl stop cape.service" in msg
    finally:
        cuckoo_mod._CUCKOO_LOCK_FD = lock_file
        cuckoo_mod._release_cuckoo_lock()

    # Lock must now be acquirable again
    probe = open(tmp_path / "log" / "cuckoo.lock", "r+")
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(probe, fcntl.LOCK_UN)
    finally:
        probe.close()


def test_cuckoo_forked_child_closes_inherited_lock_fd(tmp_path):
    cuckoo_mod._release_cuckoo_lock()
    lock_file = cuckoo_mod._acquire_cuckoo_lock(str(tmp_path))
    assert lock_file is not None

    ready_r, ready_w = os.pipe()
    hold_r, hold_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        os.close(hold_w)
        os.write(ready_w, b"1")
        os.close(ready_w)
        os.read(hold_r, 1)
        os.close(hold_r)
        os._exit(0)

    os.close(ready_w)
    os.close(hold_r)
    try:
        assert os.read(ready_r, 1) == b"1"
        cuckoo_mod._release_cuckoo_lock()

        probe = open(tmp_path / "log" / "cuckoo.lock", "r+")
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(probe, fcntl.LOCK_UN)
        finally:
            probe.close()
    finally:
        os.close(ready_r)
        os.close(hold_w)
        os.waitpid(pid, 0)


def test_cuckoo_init_acquires_lock_before_mutating_tasks_or_routing(monkeypatch, tmp_path):
    called = []
    monkeypatch.setattr(cuckoo_mod, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(cuckoo_mod, "logo", lambda: called.append("logo"))
    monkeypatch.setattr(cuckoo_mod, "check_working_directory", lambda: called.append("cwd"))
    monkeypatch.setattr(cuckoo_mod, "check_configs", lambda: called.append("configs"))
    monkeypatch.setattr(cuckoo_mod, "create_structure", lambda: (tmp_path / "log").mkdir(exist_ok=True))
    monkeypatch.setattr(cuckoo_mod, "init_database", lambda: called.append("db"))
    monkeypatch.setattr(cuckoo_mod, "init_logging", lambda _lvl: called.append("log"))
    monkeypatch.setattr(cuckoo_mod, "check_webgui_mongo", lambda: called.append("mongo"))
    monkeypatch.setattr(cuckoo_mod, "init_modules", lambda: called.append("modules"))
    monkeypatch.setattr(cuckoo_mod, "init_tasks", lambda: called.append("init_tasks"))
    monkeypatch.setattr(cuckoo_mod, "init_rooter", lambda **_kw: called.append("init_rooter"))
    monkeypatch.setattr(cuckoo_mod, "init_routing", lambda **_kw: called.append("init_routing"))
    monkeypatch.setattr(cuckoo_mod, "ResultServer", lambda: called.append("ResultServer"))

    # Hold the lock in another open file descriptor before calling cuckoo_init
    (tmp_path / "log").mkdir(exist_ok=True)
    holder = open(tmp_path / "log" / "cuckoo.lock", "w+")
    holder.write("99999\n")
    holder.flush()
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    cuckoo_mod._release_cuckoo_lock()

    orig_cwd = os.getcwd()
    try:
        with pytest.raises(CuckooStartupError, match="PID 99999"):
            cuckoo_mod.cuckoo_init()
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        holder.close()

    assert os.getcwd() == orig_cwd
    assert "init_tasks" not in called
    assert "init_rooter" not in called
    assert "init_routing" not in called
    assert "ResultServer" not in called


def test_log_critical_error_suppresses_traceback_for_startup_error_unless_debug(monkeypatch):
    recorded = []

    class _CaptureHandler(logging.Handler):
        def emit(self, record):
            recorded.append(record)

    handler = _CaptureHandler()
    monkeypatch.setattr(cuckoo_mod.log, "handlers", [handler])

    try:
        raise CuckooStartupError("port 2042 in use")
    except CuckooCriticalError as exc:
        cuckoo_mod._log_critical_error(exc, debug=False)
        cuckoo_mod._log_critical_error(exc, debug=True)

    try:
        raise CuckooCriticalError("unexpected internal failure")
    except CuckooCriticalError as exc:
        cuckoo_mod._log_critical_error(exc, debug=False)

    assert len(recorded) == 3
    assert not recorded[0].exc_info
    assert isinstance(recorded[1].exc_info, tuple)
    assert isinstance(recorded[2].exc_info, tuple)
