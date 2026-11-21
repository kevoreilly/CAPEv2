# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import errno
import logging
import socket
from ctypes import addressof, byref, c_void_p, create_string_buffer, sizeof
from threading import Lock, Thread

from lib.common.defines import (
    ADVAPI32,
    BOOL,
    DWORD,
    ERROR_MORE_DATA,
    ERROR_PIPE_CONNECTED,
    HANDLE,
    INVALID_HANDLE_VALUE,
    KERNEL32,
    LPVOID,
    PIPE_ACCESS_INBOUND,
    PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
    PWSTR,
    SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR,
)

log = logging.getLogger()

BUFSIZE = 512
LOGBUFSIZE = 16384
INVALID_HANDLE_VALUE_PTR = c_void_p(-1).value
_CLOSED_SOCKET_ERRNOS = {errno.EBADF, getattr(errno, "WSAENOTSOCK", errno.EBADF)}

# Ensure WinAPI returns proper handle-sized values on 64-bit.
KERNEL32.CloseHandle.argtypes = [HANDLE]
KERNEL32.CloseHandle.restype = BOOL
KERNEL32.ConnectNamedPipe.argtypes = [HANDLE, LPVOID]
KERNEL32.ConnectNamedPipe.restype = BOOL
KERNEL32.CreateNamedPipeW.argtypes = [PWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPVOID]
KERNEL32.CreateNamedPipeW.restype = HANDLE
KERNEL32.GetLastError.argtypes = []
KERNEL32.GetLastError.restype = DWORD
KERNEL32.ReadFile.argtypes = [HANDLE, LPVOID, DWORD, LPVOID, LPVOID]
KERNEL32.ReadFile.restype = BOOL


class LogServerThread(Thread):
    """Cuckoo Log Server.

    This Log Server receives the BSON-encoded logs from cuckoomon loaded in an individual process
    and forwards them on to the resultserver on the process' behalf, avoiding the need for winsock
    in cuckoomon and escaping some deadlock issues that can arise from the use of winsock APIs at
    crucial points in process execution (like the final termination) and also allowing us to again
    use synchronous logging without side-effects.
    """

    def __init__(self, h_pipe, result_ip, result_port):
        """@param pipe_name: Cuckoo Log Server PIPE name."""
        Thread.__init__(self)
        self._lock = Lock()
        self.h_pipe = h_pipe
        self.resultserver_ip = result_ip
        self.resultserver_port = result_port
        self.resultserver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.resultserver_socket.connect((self.resultserver_ip, self.resultserver_port))
        except Exception:
            self.resultserver_socket.close()
            raise
        self.do_run = True

    def _close_resources(self):
        with self._lock:
            h_pipe, self.h_pipe = self.h_pipe, 0
        try:
            self.resultserver_socket.close()
        except OSError:
            pass
        if h_pipe and h_pipe not in (INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE_PTR):
            KERNEL32.CloseHandle(h_pipe)

    def stop(self):
        """Stop Log Server."""
        self.do_run = False
        self._close_resources()

    def handle_logs(self):
        # Read the data submitted to the Log Server.
        buf = create_string_buffer(LOGBUFSIZE)
        bytes_read = DWORD(0)
        while self.do_run:
            chunks = []
            memory_error = False
            while True:
                bytes_read.value = 0
                h_pipe = self.h_pipe
                if not h_pipe:
                    success = 0
                    break
                success = KERNEL32.ReadFile(h_pipe, buf, sizeof(buf), byref(bytes_read), None)
                err = 0 if success else KERNEL32.GetLastError()
                if (success or err == ERROR_MORE_DATA) and bytes_read.value > 0:
                    if not memory_error:
                        try:
                            chunks.append(buf.raw[: bytes_read.value])
                        except MemoryError:
                            log.error("MemoryError just occurred")
                            chunks.clear()
                            memory_error = True
                if success or err != ERROR_MORE_DATA:
                    break

            if not success:
                # ReadFile failed without returning a complete message: the client end of the pipe
                # is gone (e.g. the monitored process exited). Discard any partial chunks and stop
                # instead of busy-looping or forwarding truncated BSON frames.
                self.do_run = False
                break

            # got an entire message, send it off to the resultserver
            if not memory_error and chunks:
                data = chunks[0] if len(chunks) == 1 else b"".join(chunks)
                try:
                    self.resultserver_socket.sendall(data)
                except OSError as e:
                    if self.do_run and e.errno not in _CLOSED_SOCKET_ERRNOS:
                        log.warning("Failed to forward log data to resultserver: %s", e)
                    self.do_run = False
                    break

    def run(self):
        """Create and run Log Server.
        @return: operation status.
        """
        try:
            if self.do_run:
                # Create the Named Pipe.
                # If we receive a connection to the pipe, we invoke the handler.
                h_pipe = self.h_pipe
                if h_pipe and (KERNEL32.ConnectNamedPipe(h_pipe, None) or KERNEL32.GetLastError() == ERROR_PIPE_CONNECTED):
                    self.handle_logs()

            return True
        except Exception:
            log.exception("LogServerThread failed")
            return True
        finally:
            self.do_run = False
            self._close_resources()


class LogServer:
    def __init__(self, result_ip, result_port, logserver_path):
        self.thread = None
        # Create the Named Pipe.
        sd = SECURITY_DESCRIPTOR()
        sa = SECURITY_ATTRIBUTES()
        ADVAPI32.InitializeSecurityDescriptor(byref(sd), 1)
        ADVAPI32.SetSecurityDescriptorDacl(byref(sd), True, None, False)
        sa.nLength = sizeof(SECURITY_ATTRIBUTES)
        sa.bInheritHandle = False
        sa.lpSecurityDescriptor = addressof(sd)

        h_pipe = KERNEL32.CreateNamedPipeW(
            logserver_path,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFSIZE,
            LOGBUFSIZE,
            0,
            byref(sa),
        )

        if not h_pipe or h_pipe in (INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE_PTR):
            log.warning("Unable to create log server pipe")
            return

        try:
            logserver = LogServerThread(h_pipe, result_ip, result_port)
        except OSError as e:
            KERNEL32.CloseHandle(h_pipe)
            log.warning("Unable to connect log server to resultserver (%s:%s): %s", result_ip, result_port, e)
            return

        logserver.daemon = True
        logserver.start()
        self.thread = logserver

    def stop(self):
        if self.thread is not None:
            self.thread.stop()
