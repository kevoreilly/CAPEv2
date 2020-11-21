# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import socket
import logging
import traceback
from ctypes import create_string_buffer, create_unicode_buffer
from ctypes import byref, c_int, sizeof, addressof
from threading import Thread

from lib.common.defines import ADVAPI32, KERNEL32
from lib.common.defines import ERROR_MORE_DATA, ERROR_PIPE_CONNECTED
from lib.common.defines import PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE
from lib.common.defines import PIPE_READMODE_MESSAGE, PIPE_WAIT
from lib.common.defines import PIPE_UNLIMITED_INSTANCES, INVALID_HANDLE_VALUE
from lib.common.defines import SECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES

log = logging.getLogger()

BUFSIZE = 512
LOGBUFSIZE = 16384


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
        self.h_pipe = h_pipe
        self.resultserver_ip = result_ip
        self.resultserver_port = result_port
        self.resultserver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.resultserver_socket.connect((self.resultserver_ip, self.resultserver_port))
        self.do_run = True

    def stop(self):
        """Stop Log Server."""
        self.do_run = False
        self.resultserver_socket.close()
        if self.h_pipe != 0:
            KERNEL32.CloseHandle(self.h_pipe)

    def handle_logs(self):
        # Read the data submitted to the Log Server.
        while True:
            data = b""
            while True:
                bytes_read = c_int(0)
                buf = create_string_buffer(LOGBUFSIZE)
                success = KERNEL32.ReadFile(self.h_pipe, buf, sizeof(buf), byref(bytes_read), None)
                try:
                    data += buf.raw[:bytes_read.value]
                except MemoryError:
                    log.error("MemoryError just happend")
                    break
                if success or KERNEL32.GetLastError() != ERROR_MORE_DATA:
                    break

            # got an entire message, send it off to the resultserver
            if data:
                self.resultserver_socket.sendall(data)

    def run(self):
        """Create and run Log Server.
        @return: operation status.
        """
        try:
            while self.do_run:
                # Create the Named Pipe.
                # If we receive a connection to the pipe, we invoke the handler.
                if KERNEL32.ConnectNamedPipe(self.h_pipe, None) or KERNEL32.GetLastError() == ERROR_PIPE_CONNECTED:
                    self.handle_logs()

                KERNEL32.CloseHandle(self.h_pipe)
                self.resultserver_socket.close()

            return True
        except Exception as e:
            print(e)
            self.resultserver_socket.close()
            if self.h_pipe != 0:
                KERNEL32.CloseHandle(self.h_pipe)
            error_exc = traceback.format_exc()
            log.exception(error_exc)
            return True


class LogServer(object):
    def __init__(self, result_ip, result_port, logserver_path):
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

        if h_pipe == INVALID_HANDLE_VALUE:
            log.warning("Unable to create log server pipe.")
            return False

        logserver = LogServerThread(h_pipe, result_ip, result_port)
        logserver.daemon = True
        logserver.start()
