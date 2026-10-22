"""Tests for lib.core.pipe."""

import unittest
from ctypes import create_string_buffer
from unittest.mock import MagicMock, patch

from lib.core import pipe as pipe_mod
from lib.core.pipe import PipeDispatcher, PipeServer

ERROR_MORE_DATA = 234


class FakeKernel32:
    """Feeds canned pipe reads to PipeDispatcher._read_message."""

    def __init__(self, reads):
        # reads: list of (payload, last_error, success)
        self.reads = list(reads)
        self.last_error = 0

    def ReadFile(self, handle, buf, size, bytes_read, overlapped):
        payload, last_error, success = self.reads.pop(0)
        self.last_error = last_error
        # byref() gives a CArgObject; _obj is the buffer it points at.
        target = buf._obj
        target.raw = payload.ljust(len(target.raw), b"\x00")
        bytes_read._obj.value = len(payload)
        return success

    def GetLastError(self):
        return self.last_error


class TestReadMessage(unittest.TestCase):
    def _read(self, reads):
        dispatcher = PipeDispatcher(pipe_handle=1, dispatcher=MagicMock())
        with patch.object(pipe_mod, "KERNEL32", FakeKernel32(reads)):
            return dispatcher._read_message(create_string_buffer(64))

    def test_plain_message(self):
        self.assertEqual(b"PROCESS:123", self._read([(b"PROCESS:123", 0, True)]))

    def test_nul_terminated_message_loses_the_terminator(self):
        self.assertEqual(b"PROCESS:123", self._read([(b"PROCESS:123\x00", 0, True)]))

    def test_embedded_nul_is_preserved(self):
        """buf.value stopped at the first NUL, so the tail of the message was
        dropped and never reached the dispatcher."""
        self.assertEqual(b"FILE_DUMP:a\x00b", self._read([(b"FILE_DUMP:a\x00b\x00", 0, True)]))

    def test_message_split_over_several_reads(self):
        reads = [
            (b"PROCE", ERROR_MORE_DATA, False),
            (b"SS:12", ERROR_MORE_DATA, False),
            (b"3", 0, True),
        ]
        self.assertEqual(b"PROCESS:123", self._read(reads))

    def test_failed_read_returns_none(self):
        self.assertIsNone(self._read([(b"", 6, False)]))


class TestPipeServerFailureBackoff(unittest.TestCase):
    def test_creation_failure_sleeps_and_gives_up(self):
        """Without a delay this was a spin loop for the rest of the analysis."""
        kernel32 = MagicMock()
        kernel32.CreateNamedPipeW.return_value = None
        kernel32.GetLastError.return_value = 5

        server = PipeServer(MagicMock(), "\\\\.\\PIPE\\test")
        with patch.object(pipe_mod, "KERNEL32", kernel32), patch.object(pipe_mod, "ADVAPI32", MagicMock()):
            server.run()

        self.assertEqual(pipe_mod.MAX_PIPE_FAILURES, kernel32.CreateNamedPipeW.call_count)
        self.assertEqual(pipe_mod.MAX_PIPE_FAILURES - 1, kernel32.Sleep.call_count)
        kernel32.Sleep.assert_called_with(pipe_mod.PIPE_RETRY_DELAY_MS)

    def test_finished_handlers_are_not_retained(self):
        kernel32 = MagicMock()
        kernel32.CreateNamedPipeW.return_value = 4242
        kernel32.ConnectNamedPipe.return_value = True

        created = []

        def make_handler(pipe_handle, **kwargs):
            handler = MagicMock()
            # The first handler has already finished by the next accept.
            handler.is_alive.return_value = bool(created)
            created.append(handler)
            if len(created) == 2:
                server.do_run = False
            return handler

        server = PipeServer(make_handler, "\\\\.\\PIPE\\test")
        with patch.object(pipe_mod, "KERNEL32", kernel32), patch.object(pipe_mod, "ADVAPI32", MagicMock()):
            server.run()

        self.assertEqual(2, len(created))
        self.assertNotIn(created[0], server.handlers)
        self.assertIn(created[1], server.handlers)


if __name__ == "__main__":
    unittest.main()
