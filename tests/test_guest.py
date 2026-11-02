"""Exercise retries at the guest HTTP transport boundary."""

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Lock, Thread

import pytest
import requests
from urllib3.util import connection

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

    with pytest.raises(requests.ReadTimeout):
        manager.post("/execute", data={"command": "analyzer", "async": "yes"}, timeout=(1, 0.25))

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
