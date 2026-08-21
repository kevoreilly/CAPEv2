"""Regression tests for SuricataSC.json_recv EOF handling.

A crashed/restarted suricata daemon closes the command socket mid-analysis.
select() reports a closed socket as readable, and json_recv()'s old
`while True: recv()` loop had no EOF guard — so recv() returning b'' spun the
loop forever, hanging the whole processing task until the 900s pebble timeout
killed it (status=failed_processing, NO report). The fix bails on empty recv so
send_command() raises and the caller degrades gracefully (report still built).
"""
from lib.cuckoo.common.suricatasc import SuricataSC


class _FakeSock:
    """Minimal socket stand-in; recv() yields queued chunks then EOF (b'')."""

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self._empty = 0

    def recv(self, _n):
        if self._chunks:
            return self._chunks.pop(0)
        self._empty += 1
        # A correct json_recv breaks on the first empty recv; a regression would
        # spin here forever — fail loudly instead of hanging the test suite.
        if self._empty > 5:
            raise AssertionError("json_recv looped on EOF (regression)")
        return b""

    def close(self):
        pass


def _sc(chunks):
    sc = SuricataSC("/tmp/suricatasc-test-nonexistent.sock")  # __init__ makes an unconnected socket
    sc.socket.close()
    sc.socket = _FakeSock(chunks)
    return sc


def test_json_recv_eof_returns_without_hanging():
    # peer closed immediately (crash before any reply)
    assert _sc([b""]).json_recv() is None


def test_json_recv_partial_then_eof():
    # crash mid-reply: partial JSON with no trailing newline, then EOF
    assert _sc([b'{"return"', b""]).json_recv() is None


def test_json_recv_complete_line_parses():
    assert _sc([b'{"return": "OK"}\n']).json_recv() == {"return": "OK"}


def test_json_recv_chunked_line_parses():
    # reply split across recv() calls, terminated by newline
    assert _sc([b'{"ret', b'urn": "OK"}\n']).json_recv() == {"return": "OK"}
