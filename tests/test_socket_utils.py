import json
import os
import shutil
import socket
import tempfile
import threading

import pytest

from lib.cuckoo.common import socket_utils
from lib.cuckoo.common.socket_utils import send_socket_command


@pytest.fixture
def short_dir():
    # AF_UNIX paths are limited to 108 bytes; pytest's tmp_path can get close to that.
    d = tempfile.mkdtemp(prefix="cst")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def reply_tmp(short_dir, monkeypatch):
    """Redirect mkdtemp() so the test can check that reply sockets are cleaned up."""
    d = os.path.join(short_dir, "r")
    os.mkdir(d)
    monkeypatch.setattr(tempfile, "tempdir", d)
    return d


class FakeRooter:
    """Minimal datagram server modelled on utils/rooter.py."""

    def __init__(self, path, reply=True):
        self.path = path
        self.reply = reply
        self.requests = []
        self.addrs = []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.server.bind(path)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        data, addr = self.server.recvfrom(4096)
        self.requests.append(json.loads(data))
        self.addrs.append(addr)
        if self.reply:
            self.server.sendto(json.dumps({"output": "ok", "exception": None}).encode(), addr)

    def close(self):
        self.thread.join(timeout=5)
        self.server.close()


def test_send_socket_command_roundtrip(short_dir, reply_tmp):
    server = FakeRooter(os.path.join(short_dir, "rooter"))
    try:
        resp = send_socket_command(server.path, "nic_available", "eth0", socket_timeout=5, flag="x")
    finally:
        server.close()

    assert resp == {"output": "ok", "exception": None}
    # socket_timeout is a client option and must not be forwarded to the server.
    assert server.requests == [{"command": "nic_available", "args": ["eth0"], "kwargs": {"flag": "x"}}]
    assert os.listdir(reply_tmp) == []


def test_send_socket_command_timeout_cleans_up(short_dir, reply_tmp):
    server = FakeRooter(os.path.join(short_dir, "rooter"), reply=False)
    try:
        resp = send_socket_command(server.path, "nic_available", "eth0", socket_timeout=0.2)
    finally:
        server.close()

    assert resp == {"exception": f"{server.path} response timeout", "output": ""}
    assert os.listdir(reply_tmp) == []
    # A late reply from the rooter now hits a missing path: this is what utils.rooter.send_response must survive.
    late = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        with pytest.raises(FileNotFoundError):
            late.sendto(b"{}", server.addrs[0])
    finally:
        late.close()


def test_send_socket_command_sets_explicit_timeout(short_dir, reply_tmp, monkeypatch):
    """The wait must be bounded even without a process-wide socket.setdefaulttimeout()."""
    monkeypatch.setattr(socket, "getdefaulttimeout", lambda: None)
    assert socket_utils.DEFAULT_SOCKET_TIMEOUT is not None
    server = FakeRooter(os.path.join(short_dir, "rooter"), reply=False)
    seen = []
    real_settimeout = socket.socket.settimeout

    def spy(self, value):
        seen.append(value)
        return real_settimeout(self, 0.2)

    monkeypatch.setattr(socket.socket, "settimeout", spy)
    try:
        resp = send_socket_command(server.path, "nic_available", "eth0")
    finally:
        server.close()

    assert seen == [socket_utils.DEFAULT_SOCKET_TIMEOUT]
    assert "response timeout" in resp["exception"]


def test_send_socket_command_connect_failure_cleans_up(short_dir, reply_tmp):
    not_a_socket = os.path.join(short_dir, "rooter")
    open(not_a_socket, "w").close()

    assert send_socket_command(not_a_socket, "nic_available", "eth0", socket_timeout=1) is None
    assert os.listdir(reply_tmp) == []


def test_send_socket_command_missing_socket_path(short_dir):
    assert send_socket_command(os.path.join(short_dir, "missing"), "nic_available") is None
