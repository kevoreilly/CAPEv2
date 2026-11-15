"""Tests for lib.core.log."""

import ctypes
import errno
import socket
import sys
import threading
import unittest
import uuid
from unittest.mock import MagicMock, patch

if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()

from lib.core import log as log_mod
from lib.core.log import INVALID_HANDLE_VALUE_PTR, LOGBUFSIZE, LogServer, LogServerThread

ERROR_BROKEN_PIPE = 0x6D
ERROR_MORE_DATA = 0xEA
ERROR_NO_DATA = 0xE8
ERROR_PIPE_CONNECTED = 0x217


class FakeKernel32:
    """Feeds scripted ConnectNamedPipe / ReadFile responses to LogServerThread."""

    def __init__(self, reads=(), connect_result=1, connect_error=0, created_handle=0x1_0000_1234):
        self.reads = list(reads)
        self.connect_result = connect_result
        self.connect_error = connect_error
        self.created_handle = created_handle
        self.last_error = 0
        self.connect_calls = []
        self.read_calls = 0
        self.closed_handles = []

    def CreateNamedPipeW(self, *args):
        return self.created_handle

    def ConnectNamedPipe(self, handle, overlapped):
        self.connect_calls.append(handle)
        self.last_error = self.connect_error
        return self.connect_result

    def ReadFile(self, handle, buf, size, bytes_read, overlapped):
        self.read_calls += 1
        if not self.reads:
            self.last_error = ERROR_BROKEN_PIPE
            bytes_read._obj.value = 0
            return 0
        item = self.reads.pop(0)
        if callable(item):
            return item(self, handle, buf, size, bytes_read, overlapped)
        payload, last_error, success = item
        self.last_error = last_error
        buf.raw = payload.ljust(len(buf), b"\x00")
        bytes_read._obj.value = len(payload)
        return 1 if success else 0

    def GetLastError(self):
        return self.last_error

    def CloseHandle(self, handle):
        self.closed_handles.append(handle)
        return 1


def _make_thread(h_pipe=0x1_0000_1234, sock=None):
    """Construct LogServerThread with a mock resultserver socket without network I/O."""
    mock_sock = sock or MagicMock(spec=socket.socket)
    with patch("lib.core.log.socket.socket", return_value=mock_sock):
        thread = LogServerThread(h_pipe, "127.0.0.1", 2042)
    return thread, mock_sock


class TestLogServerThread(unittest.TestCase):
    def test_win64_argtypes_configured(self):
        self.assertEqual([log_mod.HANDLE], log_mod.KERNEL32.CloseHandle.argtypes)
        self.assertEqual([log_mod.HANDLE, log_mod.LPVOID], log_mod.KERNEL32.ConnectNamedPipe.argtypes)
        self.assertEqual(
            [log_mod.HANDLE, log_mod.LPVOID, log_mod.DWORD, log_mod.LPVOID, log_mod.LPVOID],
            log_mod.KERNEL32.ReadFile.argtypes,
        )
        self.assertEqual(log_mod.HANDLE, log_mod.KERNEL32.CreateNamedPipeW.restype)

    def test_single_and_multichunk_messages_then_eof(self):
        chunk1 = b"A" * 64
        chunk2 = b"B" * 64
        # Final chunk leaves stale LastError == ERROR_MORE_DATA on success=True.
        reads = [
            (b"BSON 1234\n", 0, True),
            (chunk1, ERROR_MORE_DATA, False),
            (chunk2, ERROR_MORE_DATA, True),
            (b"", ERROR_BROKEN_PIPE, False),
        ]
        k32 = FakeKernel32(reads=reads)
        thread, sock = _make_thread(h_pipe=0x2_0000_0001)

        with patch.object(log_mod, "KERNEL32", k32):
            self.assertTrue(thread.run())

        sent = [call.args[0] for call in sock.sendall.call_args_list]
        self.assertEqual([b"BSON 1234\n", chunk1 + chunk2], sent)
        self.assertFalse(thread.do_run)
        self.assertEqual([0x2_0000_0001], k32.closed_handles)
        sock.close.assert_called()

    def test_mid_message_disconnect_discards_truncated_bson_prefix(self):
        reads = [
            (b"BSON 4321\n", 0, True),
            (b"\x80\x80\x00\x00" + b"X" * 100, ERROR_MORE_DATA, False),
            (b"", ERROR_BROKEN_PIPE, False),
        ]
        k32 = FakeKernel32(reads=reads)
        thread, sock = _make_thread(h_pipe=0x42)

        with patch.object(log_mod, "KERNEL32", k32):
            thread.run()

        sent = [call.args[0] for call in sock.sendall.call_args_list]
        self.assertEqual([b"BSON 4321\n"], sent)
        self.assertEqual([0x42], k32.closed_handles)

    def test_zero_byte_message_does_not_terminate_stream(self):
        reads = [
            (b"", 0, True),
            (b"payload-after-empty", 0, True),
            (b"", ERROR_BROKEN_PIPE, False),
        ]
        k32 = FakeKernel32(reads=reads)
        thread, sock = _make_thread(h_pipe=0x55)

        with patch.object(log_mod, "KERNEL32", k32):
            thread.run()

        sent = [call.args[0] for call in sock.sendall.call_args_list]
        self.assertEqual([b"payload-after-empty"], sent)
        self.assertEqual([0x55], k32.closed_handles)

    def test_memory_error_drains_remaining_chunks_and_preserves_framing(self):
        reads = [
            (b"part-1", ERROR_MORE_DATA, False),
            (b"part-2-oom", ERROR_MORE_DATA, False),
            (b"part-3-tail", 0, True),
            (b"next-valid-bson", 0, True),
            (b"", ERROR_BROKEN_PIPE, False),
        ]
        k32 = FakeKernel32(reads=reads)
        thread, sock = _make_thread(h_pipe=0x77)

        with (
            patch.object(log_mod, "KERNEL32", k32),
            patch.object(log_mod, "create_string_buffer", wraps=log_mod.create_string_buffer) as mock_buf,
        ):
            # Simulate MemoryError when slicing the second chunk via custom buffer raw property.
            real_buf = log_mod.create_string_buffer(LOGBUFSIZE)

            class BufProxy:
                def __len__(self):
                    return LOGBUFSIZE

                @property
                def raw(self):
                    val = real_buf.raw
                    if val.startswith(b"part-2-oom"):
                        raise MemoryError
                    return val

                @raw.setter
                def raw(self, value):
                    real_buf.raw = value

            mock_buf.side_effect = lambda _size: BufProxy()
            with patch.object(log_mod, "sizeof", return_value=LOGBUFSIZE):
                thread.handle_logs()

        sent = [call.args[0] for call in sock.sendall.call_args_list]
        self.assertEqual([b"next-valid-bson"], sent)

    def test_connect_named_pipe_failure_does_not_busy_loop_or_double_close(self):
        k32 = FakeKernel32(connect_result=0, connect_error=ERROR_NO_DATA)
        thread, sock = _make_thread(h_pipe=0x99)

        with patch.object(log_mod, "KERNEL32", k32):
            self.assertTrue(thread.run())

        self.assertEqual([0x99], k32.connect_calls)
        self.assertEqual(0, k32.read_calls)
        self.assertEqual([0x99], k32.closed_handles)
        self.assertFalse(thread.do_run)
        sock.sendall.assert_not_called()

    def test_connect_named_pipe_already_connected_processes_logs(self):
        reads = [
            (b"already-connected", 0, True),
            (b"", ERROR_BROKEN_PIPE, False),
        ]
        k32 = FakeKernel32(reads=reads, connect_result=0, connect_error=ERROR_PIPE_CONNECTED)
        thread, sock = _make_thread(h_pipe=0xAB)

        with patch.object(log_mod, "KERNEL32", k32):
            thread.run()

        sent = [call.args[0] for call in sock.sendall.call_args_list]
        self.assertEqual([b"already-connected"], sent)
        self.assertEqual([0xAB], k32.closed_handles)

    def test_stop_and_run_close_handle_at_most_once(self):
        k32 = FakeKernel32(reads=[(b"", ERROR_BROKEN_PIPE, False)])
        thread, _ = _make_thread(h_pipe=0xCD)

        with patch.object(log_mod, "KERNEL32", k32):
            thread.stop()
            thread.run()
            thread.stop()

        self.assertEqual([0xCD], k32.closed_handles)
        self.assertEqual([], k32.connect_calls)

    def test_sendall_oserror_exits_cleanly_and_closes_once(self):
        reads = [(b"frame-1", 0, True), (b"frame-2", 0, True)]
        k32 = FakeKernel32(reads=reads)
        thread, sock = _make_thread(h_pipe=0xEF)
        sock.sendall.side_effect = OSError(errno.EPIPE, "Broken pipe")

        with patch.object(log_mod, "KERNEL32", k32), self.assertLogs(level="WARNING") as cm:
            thread.run()

        self.assertEqual(1, k32.read_calls)
        self.assertEqual([0xEF], k32.closed_handles)
        self.assertTrue(any("Failed to forward log data" in msg for msg in cm.output))


class TestLogServerInit(unittest.TestCase):
    def test_pipe_creation_failure_returns_none_without_type_error(self):
        for bad_handle in (None, 0, -1, INVALID_HANDLE_VALUE_PTR):
            k32 = FakeKernel32(created_handle=bad_handle)
            with patch.object(log_mod, "KERNEL32", k32), patch.object(log_mod, "ADVAPI32", MagicMock()):
                server = LogServer("127.0.0.1", 2042, "\\\\.\\PIPE\\bad")
            self.assertIsNone(server.thread)
            self.assertEqual([], k32.closed_handles)

    def test_socket_connect_failure_closes_pipe_handle_without_raising(self):
        k32 = FakeKernel32(created_handle=0x3_0000_0005)
        failing_sock = MagicMock(spec=socket.socket)
        failing_sock.connect.side_effect = OSError(errno.ECONNREFUSED, "Connection refused")

        with (
            patch.object(log_mod, "KERNEL32", k32),
            patch.object(log_mod, "ADVAPI32", MagicMock()),
            patch("lib.core.log.socket.socket", return_value=failing_sock),
        ):
            server = LogServer("127.0.0.1", 2042, "\\\\.\\PIPE\\connfail")

        self.assertIsNone(server.thread)
        failing_sock.close.assert_called_once()
        self.assertEqual([0x3_0000_0005], k32.closed_handles)


@unittest.skipUnless(sys.platform == "win32", "Windows named pipe integration test")
class TestLogServerWin32Integration(unittest.TestCase):
    def test_real_named_pipe_multichunk_and_clean_exit(self):
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
        ]
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.WriteFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        k32.WriteFile.restype = ctypes.c_int
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.restype = ctypes.c_int

        received = bytearray()
        done_recv = threading.Event()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def accept_and_drain():
            try:
                conn, _ = listener.accept()
                with conn:
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        received.extend(chunk)
            finally:
                listener.close()
                done_recv.set()

        server_thread = threading.Thread(target=accept_and_drain, daemon=True)
        server_thread.start()

        pipe_name = f"\\\\.\\pipe\\cape_test_log_{uuid.uuid4().hex}"
        log_server = LogServer("127.0.0.1", port, pipe_name)
        self.assertIsNotNone(log_server.thread)

        generic_write = 0x40000000
        open_existing = 3
        client = k32.CreateFileW(pipe_name, generic_write, 0, None, open_existing, 0, None)
        self.assertNotIn(client, (None, 0, INVALID_HANDLE_VALUE_PTR))

        msg1 = b"BSON 9999\n"
        msg2 = b"M" * (LOGBUFSIZE * 2 + 321)
        written = ctypes.c_uint(0)
        try:
            self.assertTrue(k32.WriteFile(client, msg1, len(msg1), ctypes.byref(written), None))
            self.assertTrue(k32.WriteFile(client, msg2, len(msg2), ctypes.byref(written), None))
        finally:
            k32.CloseHandle(client)

        log_server.thread.join(timeout=5)
        self.assertFalse(log_server.thread.is_alive())
        self.assertTrue(done_recv.wait(timeout=5))
        self.assertEqual(msg1 + msg2, bytes(received))


if __name__ == "__main__":
    unittest.main()
