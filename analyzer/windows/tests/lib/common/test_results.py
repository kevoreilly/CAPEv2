"""Tests for lib.common.results."""

import socket
import unittest
from io import BytesIO

from lib.common.results import BUFSIZE, NetlogConnection


class FakeSocket:
    def __init__(self, fail_first=False):
        self.writes = []
        self.fail_first = fail_first

    def sendall(self, data):
        if self.fail_first:
            self.fail_first = False
            raise socket.error("connection reset")
        self.writes.append(data)


class TestSendFileobj(unittest.TestCase):
    def _conn(self, sock):
        # NetlogConnection.__init__ reads the analysis config, which is not
        # present outside a real analysis.
        conn = NetlogConnection.__new__(NetlogConnection)
        conn.proto = b""
        conn.sock = sock
        return conn

    def test_binary_payload_is_not_split_on_newlines(self):
        """Iterating a file object yields lines, so binary data used to be sent
        one 0x0A delimited fragment at a time."""
        payload = bytes(range(256)) * 400  # 102400 bytes, 400 newline bytes
        self.assertGreater(payload.count(b"\n"), 100)

        sock = FakeSocket()
        self._conn(sock).send_fileobj(BytesIO(payload))

        self.assertEqual(1, len(sock.writes))
        self.assertEqual(payload, b"".join(sock.writes))

    def test_chunks_are_bufsize(self):
        payload = b"A" * (BUFSIZE * 2 + 17)

        sock = FakeSocket()
        self._conn(sock).send_fileobj(BytesIO(payload))

        self.assertEqual([BUFSIZE, BUFSIZE, 17], [len(w) for w in sock.writes])
        self.assertEqual(payload, b"".join(sock.writes))

    def test_empty_payload_sends_nothing(self):
        sock = FakeSocket()
        self._conn(sock).send_fileobj(BytesIO(b""))
        self.assertEqual([], sock.writes)

    def test_reads_from_current_position(self):
        buf = BytesIO(b"headerbody")
        buf.seek(6)

        sock = FakeSocket()
        self._conn(sock).send_fileobj(buf)

        self.assertEqual(b"body", b"".join(sock.writes))

    def test_send_failure_reconnects_and_retries(self):
        """A bare sock.send() bypassed this; the payload was simply lost."""
        payload = b"screenshot bytes"
        good = FakeSocket()
        conn = self._conn(FakeSocket(fail_first=True))

        def reconnect():
            conn.sock = good

        conn.connect = reconnect
        conn.send_fileobj(BytesIO(payload))

        self.assertEqual(payload, b"".join(good.writes))


if __name__ == "__main__":
    unittest.main()
