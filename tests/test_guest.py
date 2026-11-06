"""Exercise retries at the guest HTTP transport boundary."""

from collections import Counter
from email import message_from_bytes
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from threading import Event, Lock, Thread
import time

import pytest
import requests
from urllib3.exceptions import ProtocolError
from urllib3.util import connection

from lib.cuckoo.common.exceptions import CuckooGuestError
from lib.cuckoo.core import guest as guest_mod
from lib.cuckoo.core.guest import GuestManager


@pytest.fixture
def guest_endpoint():
    received = Counter()
    lock = Lock()
    release = Event()

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            key = (self.command, self.path)
            with lock:
                received[key] += 1
                first_request = received[key] == 1
            # The agent has accepted the request, but its response is delayed.
            if first_request and self.path != "/store":
                release.wait(5)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ready")
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_GET = handle_request
        do_POST = handle_request

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    worker.start()
    manager = GuestManager("test", "127.0.0.1", "windows", 1, None)
    manager.port = server.server_port
    try:
        yield manager, received
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def test_post_does_not_replay_accepted_execution(guest_endpoint):
    manager, received = guest_endpoint

    with pytest.raises(CuckooGuestError, match="timed out") as exc_info:
        manager.post("/execute", data={"command": "analyzer", "async": "yes"}, timeout=(1, 0.25))

    assert isinstance(exc_info.value.__cause__, requests.ReadTimeout)
    assert "agent.py (>= 0.10)" not in str(exc_info.value)
    assert received[("POST", "/execute")] == 1


def test_get_retries_a_delayed_response(guest_endpoint):
    manager, received = guest_endpoint

    response = manager.get("/status", timeout=(1, 0.25))

    assert response.status_code == 200
    assert response.content == b"ready"
    assert received[("GET", "/status")] == 2


def test_post_retries_before_a_connection_is_established(guest_endpoint, monkeypatch):
    manager, received = guest_endpoint
    create_connection = connection.create_connection
    attempts = []

    def refuse_first_connection(*args, **kwargs):
        attempts.append(args[0])
        if len(attempts) == 1:
            raise ConnectionRefusedError("guest agent is not listening yet")
        return create_connection(*args, **kwargs)

    monkeypatch.setattr(connection, "create_connection", refuse_first_connection)

    response = manager.post("/store", data=b"analyzer", timeout=(1, 0.25))

    assert response.status_code == 200
    assert response.content == b"ready"
    assert len(attempts) == 2
    assert received[("POST", "/store")] == 1


def test_post_distinguishes_nested_socket_timeout_from_legacy_agent_error(monkeypatch):
    manager = GuestManager("test", "127.0.0.1", "windows", 1, None)

    class DummySession:
        def __init__(self, exc):
            self._exc = exc

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            raise self._exc

    timeout_Abort = requests.ConnectionError(ProtocolError("Connection aborted.", TimeoutError("timed out")))
    monkeypatch.setattr(manager, "_guest_http_session", lambda: DummySession(timeout_Abort))
    with pytest.raises(CuckooGuestError, match="HTTP request to /store timed out"):
        manager.post("/store", data=b"x")

    reset_abort = requests.ConnectionError(
        ProtocolError("Connection aborted.", ConnectionResetError(104, "Connection reset by peer"))
    )
    monkeypatch.setattr(manager, "_guest_http_session", lambda: DummySession(reset_abort))
    with pytest.raises(CuckooGuestError, match=r"agent\.py \(>= 0\.10\)"):
        manager.post("/store", data=b"x")


def test_upload_timeout_scales_with_payload_size(monkeypatch):
    monkeypatch.setitem(guest_mod.cfg.timeouts, "guest_upload", 300)
    assert GuestManager._upload_timeout(1024) == (30, 300)
    # 250 MiB -> 60 + 512000 / 512 = 560s > 300s base timeout
    assert GuestManager._upload_timeout(250 * 1024 * 1024) == (30, 560)


def test_store_file_streams_with_content_length_and_rewinds_on_connect_retry(tmp_path, monkeypatch):
    payload = (b"MZ\x90\x00line1\r\nline2\nline3\r\x00\xff" * 24000)[: 384 * 1024]
    sample_file = tmp_path / "sample.run"
    sample_file.write_bytes(payload)

    captured = {}

    class SlowServer(ThreadingHTTPServer):
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            super().server_bind()

    class SlowStoreHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            captured["transfer_encoding"] = self.headers.get("Transfer-Encoding")
            content_type = self.headers.get("Content-Type", "")
            captured["content_type"] = content_type
            content_length = int(self.headers.get("Content-Length", "0"))
            captured["content_length"] = content_length

            chunks = []
            remaining = content_length
            while remaining > 0:
                piece = self.rfile.read(min(32 * 1024, remaining))
                if not piece:
                    break
                chunks.append(piece)
                remaining -= len(piece)
                time.sleep(0.04)

            raw_body = b"".join(chunks)
            ct_msg = message_from_bytes(
                b"Content-Type: " + content_type.encode("utf-8") + b"\r\n\r\n",
                policy=email_policy,
            )
            boundary = ct_msg.get_param("boundary").encode("ascii")
            for raw_part in raw_body.split(b"--" + boundary):
                if not raw_part or raw_part.startswith(b"--"):
                    continue
                part = raw_part.lstrip(b"\r\n")
                if part.endswith(b"\r\n"):
                    part = part[:-2]
                hdr_bytes, body_bytes = part.split(b"\r\n\r\n", 1)
                hdr_msg = message_from_bytes(hdr_bytes + b"\r\n\r\n", policy=email_policy)
                name = hdr_msg.get_param("name", header="content-disposition")
                if hdr_msg.get_filename():
                    captured["filename"] = hdr_msg.get_filename()
                    captured["file_bytes"] = body_bytes
                elif name:
                    captured[name] = body_bytes.decode("utf-8")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"message": "Successfully stored file"}')

        def log_message(self, *args):
            pass

    server = SlowServer(("127.0.0.1", 0), SlowStoreHandler)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    worker.start()

    create_connection = connection.create_connection
    attempts = []

    def refuse_first_connection(*args, **kwargs):
        attempts.append(args[0])
        if len(attempts) == 1:
            raise ConnectionRefusedError("guest agent starting")
        sock = create_connection(*args, **kwargs)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        return sock

    monkeypatch.setattr(connection, "create_connection", refuse_first_connection)
    # With 4 KiB socket buffers, total upload sleeps ~0.48s across 12 chunks while each chunk completes
    # well under the 0.25s socket timeout.
    monkeypatch.setattr(GuestManager, "_upload_timeout", staticmethod(lambda _size: (1, 0.25)))

    manager = GuestManager("test", "127.0.0.1", "linux", 42, None)
    manager.port = server.server_port
    try:
        t0 = time.monotonic()
        resp = manager._store_file(str(sample_file), "/tmp/42/test.run", filename="sample.bin")
        elapsed = time.monotonic() - t0
        assert resp.status_code == 200
        assert elapsed >= 0.40
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)

    assert len(attempts) == 2
    assert captured["transfer_encoding"] is None
    assert captured["content_length"] > len(payload)
    assert captured["filepath"] == "/tmp/42/test.run"
    assert captured["filename"] == "sample.bin"
    assert captured["file_bytes"] == payload
