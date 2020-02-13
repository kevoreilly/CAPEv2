# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import json
import socket
import select
import errno
import logging
import datetime
import socketserver
from threading import Event, Thread, Lock

import gevent.pool
import gevent.server
import gevent.socket
#https://github.com/cuckoosandbox/cuckoo/blob/13cbe0d9e457be3673304533043e992ead1ea9b2/cuckoo/core/resultserver.py#L9
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.files import open_exclusive
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooResultError
#from lib.cuckoo.common.netlog import BsonParser
from lib.cuckoo.common.utils import create_folder, Singleton, logtime, sanitize_pathname
from lib.cuckoo.common.abstracts import ProtocolHandler
from lib.cuckoo.core.log import task_log_start, task_log_stop
import six

log = logging.getLogger()
cfg = Config()

# Maximum line length to read for netlog messages, to avoid memory exhaustion
MAX_NETLOG_LINE = 4 * 1024

# Maximum number of bytes to buffer for a single connection
BUFSIZE = 16 * 1024

# Prevent malicious clients from using potentially dangerous filenames
# E.g. C API confusion by using null, or using the colon on NTFS (Alternate
# Data Streams); XXX: just replace illegal chars?
BANNED_PATH_CHARS = b'\x00:'

# Directories in which analysis-related files will be stored; also acts as
# whitelist
RESULT_UPLOADABLE = (b'CAPE', b'aux', b'buffer', b'curtain', b'extracted', b'files', b'memory', b'memory', b'shots', b'sysmon', b'procdump')
RESULT_DIRECTORIES = RESULT_UPLOADABLE + (b"reports", b"logs")

def netlog_sanitize_fname(path):
    """Validate agent-provided path for result files"""
    path = path.replace(b"\\", b"/")
    dir_part, name = os.path.split(path)
    if dir_part not in RESULT_UPLOADABLE:
        raise CuckooOperationalError("Netlog client requested banned path: %r"
                                     % path)
    if any(c in BANNED_PATH_CHARS for c in name):
        for c in BANNED_PATH_CHARS:
            path.replace(bytes([c]), b"X")

    return path

class Disconnect(Exception):
    pass


class HandlerContext(object):
    """Holds context for protocol handlers.
    Can safely be cancelled from another thread, though in practice this will
    not occur often -- usually the connection between VM and the ResultServer
    will be reset during shutdown."""
    def __init__(self, task_id, storagepath, sock):
        self.task_id = task_id
        self.command = None

        # The path where artifacts will be stored
        self.storagepath = storagepath
        self.sock = sock
        self.buf = b""

    def __repr__(self):
        return "<Context for %s>" % self.command

    def cancel(self):
        """Cancel this context; gevent might complain about this with an
        exception later on."""
        try:
            self.sock.shutdown(socket.SHUT_RD)
        except socket.error:
            pass

    def read(self):
        try:
            return self.sock.recv(16384)
        except socket.timeout as e:
            print("Do we need to fix it?", e)
            return b""
        except socket.error as e:
            if e.errno == errno.EBADF:
                return b""

            if e.errno != errno.ECONNRESET:
                raise
            log.debug("Task #%s had connection reset for %r", self.task_id,
                      self)
            return b""
        except Exception as e:
            print(e)

    def drain_buffer(self):
        """Drain buffer and end buffering"""
        buf, self.buf = self.buf, None
        return buf

    def read_newline(self):
        """Read until the next newline character, but never more than
        `MAX_NETLOG_LINE`."""
        while True:
            pos = self.buf.find(b"\n")
            if pos < 0:
                if len(self.buf) >= MAX_NETLOG_LINE:
                    raise CuckooOperationalError("Received overly long line")
                buf = self.read()
                if buf == b"":
                    raise EOFError
                self.buf += buf
                continue
            line, self.buf = self.buf[:pos], self.buf[pos + 1:]
            return line

    def copy_to_fd(self, fd, max_size=None):
        if max_size:
            fd = WriteLimiter(fd, max_size)
        fd.write(self.drain_buffer())
        while True:
            buf = self.read()
            if buf == b"":
                break
            fd.write(buf)
        fd.flush()


class WriteLimiter(object):
    def __init__(self, fd, remain):
        self.fd = fd
        self.remain = remain
        self.warned = False

    def write(self, buf):
        size = len(buf)
        write = min(size, self.remain)
        if write:
            self.fd.write(buf[:write])
            self.remain -= write
        if size and size != write:
            if not self.warned:
                log.warning("Uploaded file length larger than upload_max_size, "
                            "stopping upload.")
                self.fd.write(b"... (truncated)")
                self.warned = True

    def flush(self):
        self.fd.flush()


class FileUpload(ProtocolHandler):
    def init(self):
        self.upload_max_size = cfg.resultserver.upload_max_size
        self.storagepath = self.handler.storagepath
        self.fd = None
        self.filelog = os.path.join(self.handler.storagepath, "files.json")

    def handle(self):
        # Read until newline for file path, e.g.,
        # shots/0001.jpg or files/9498687557/libcurl-4.dll.bin
        self.handler.sock.settimeout(30)
        dump_path = netlog_sanitize_fname(self.handler.read_newline())

        if self.version and self.version >= 2:
            # NB: filepath is only used as metadata
            filepath = self.handler.read_newline()
            pids = list(map(int, self.handler.read_newline().split()))
            metadata = self.handler.read_newline()
            category = self.handler.read_newline()
        else:
            filepath, pids, metadata, category = None, [], b"", b""

        log.debug("Task #%s: File upload for %r", self.task_id, dump_path)
        file_path = os.path.join(self.storagepath, dump_path.decode("utf-8"))

        try:
            self.fd = open_exclusive(file_path)
        except OSError as e:
            if e.errno == errno.EEXIST:
                raise CuckooOperationalError("Analyzer for task #%s tried to "
                                             "overwrite an existing file" %
                                             self.task_id)
            raise
        #ToDo we need Windows path
        # filter screens/curtain/sysmon
        if not dump_path.startswith((b"shots/", b"curtain/", b"aux/", b"sysmon/")):
            # Append-writes are atomic
            with open(self.filelog, "a") as f:
                print(json.dumps({
                    "path": dump_path.decode("utf-8", "replace"),
                    "filepath": filepath.decode("utf-8", "replace") if filepath else "",
                    "pids": pids,
                    "metadata": metadata.decode("utf-8", "replace"),
                    "category": category.decode("utf-8") if category in (b"CAPE", b"files", b"memory", b"procdump") else ""
                }, ensure_ascii=False), file=f)

        self.handler.sock.settimeout(None)
        try:
            return self.handler.copy_to_fd(self.fd, self.upload_max_size)
        finally:
            log.debug("Task #%s uploaded file length: %s", self.task_id,
                      self.fd.tell())


class LogHandler(ProtocolHandler):
    """The live analysis log. Can only be opened once in a single session."""

    def init(self):
        self.logpath = os.path.join(self.handler.storagepath, "analysis.log")
        try:
            self.fd = open_exclusive(self.logpath, bufsize=1)
        except OSError:
            log.error("Task #%s: attempted to reopen live log analysis.log.",
                      self.task_id)
            return

        log.debug("Task #%s: live log analysis.log initialized.",
                  self.task_id)

    def handle(self):
        if self.fd:
            return self.handler.copy_to_fd(self.fd)


class BsonStore(ProtocolHandler):
    def init(self):
        # We cheat a little bit through the "version" variable, but that's
        # acceptable and backwards compatible (for now). Backwards compatible
        # in the sense that newer Cuckoo Monitor binaries work with older
        # versions of Cuckoo, the other way around doesn't apply here.
        if self.version is None:
            log.warning("Agent is sending BSON files without PID parameter, "
                        "you should probably update it")
            self.fd = None
            return

        self.fd = open(os.path.join(self.handler.storagepath,
                                    "logs", "%d.bson" % self.version), "wb")

    def handle(self):
        """Read a BSON stream, attempting at least basic validation, and
        log failures."""
        log.debug("Task #%s is sending a BSON stream.", self.task_id)
        if self.fd:
            self.handler.sock.settimeout(None)
            return self.handler.copy_to_fd(self.fd)


class GeventResultServerWorker(gevent.server.StreamServer):
    """The new ResultServer, providing a huge performance boost as well as
    implementing a new dropped file storage format avoiding small fd limits.
    The old ResultServer would start a new thread per socket, greatly impacting
    the overall performance of Cuckoo Sandbox. The new ResultServer uses
    so-called Greenlets, low overhead green-threads by Gevent, imposing much
    less kernel overhead.
    Furthermore, instead of writing each dropped file to its own location (in
    $CWD/storage/analyses/<task_id>/files/<partial_hash>_filename.ext) it's
    capable of storing all dropped files in a streamable container format. This
    is one of various steps to start being able to use less fd's in Cuckoo.
    """
    commands = {
        b"BSON": BsonStore,
        b"FILE": FileUpload,
        b"LOG": LogHandler,
    }
    task_mgmt_lock = Lock()

    def __init__(self, *args, **kwargs):
        super(GeventResultServerWorker, self).__init__(*args, **kwargs)

        # Store IP address to task_id mapping
        self.tasks = {}

        # Store running handlers for task_id
        self.handlers = {}

    def do_run(self):
        self.serve_forever()

    def add_task(self, task_id, ipaddr):
        with self.task_mgmt_lock:
            self.tasks[ipaddr] = task_id
            log.debug("Now tracking machine %s for task #%s", ipaddr, task_id)

    def del_task(self, task_id, ipaddr):
        """Delete ResultServer state and abort pending RequestHandlers. Since
        we're about to shutdown the VM, any remaining open connections can
        be considered a bug from the VM side, since all connections should
        have been closed after the analyzer signalled completion."""
        with self.task_mgmt_lock:
            if self.tasks.pop(ipaddr, None) is None:
                log.warning(
                    "ResultServer did not have a task with ID %s and IP %s",
                    task_id, ipaddr
                )
            else:
                log.debug(
                    "Stopped tracking machine %s for task #%s",
                    ipaddr, task_id
                )
            ctxs = self.handlers.pop(task_id, set())
            for ctx in ctxs:
                log.debug("Cancel %s for task %r", ctx, task_id)
                ctx.cancel()

    def create_folders(self):
        folders = ('CAPE', 'aux', 'aux', 'curtain', 'files', 'logs', 'memory', 'shots', 'sysmon', 'procdump')

        for folder in folders:
            try:
                create_folder(self.storagepath, folder=folder)
            except Exception as e:
                print(e)
            #ToDo
            #except CuckooOperationalError as e:
            #    print(e)
            #    log.error("Unable to create folder %s" % folder)
            #    return False

    def handle(self, sock, addr):
        """Handle the incoming connection.
        Gevent will close the socket when the function returns."""
        ipaddr = addr[0]

        with self.task_mgmt_lock:
            task_id = self.tasks.get(ipaddr)
            if not task_id:
                log.warning("ResultServer did not have a task for IP %s",
                            ipaddr)
                return

        self.storagepath = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))

        # Create all missing folders for this analysis.
        self.create_folders()

        ctx = HandlerContext(task_id, self.storagepath, sock)
        task_log_start(task_id)
        try:
            try:
                protocol = self.negotiate_protocol(task_id, ctx)
            except EOFError:
                return

            # Registering the context allows us to abort the handler by
            # shutting down its socket when the task is deleted; this should
            # prevent lingering sockets
            with self.task_mgmt_lock:
                # NOTE: the task may have been cancelled during the negotation
                # protocol and a different task for that IP address may have
                # been registered
                if self.tasks.get(ipaddr) != task_id:
                    log.warning("Task #%s for IP %s was cancelled during "
                                "negotiation", task_id, ipaddr)
                    return
                s = self.handlers.setdefault(task_id, set())
                s.add(ctx)

            try:
                with protocol:
                    protocol.handle()
            except CuckooOperationalError as e:
                log.error(e)
            finally:
                with self.task_mgmt_lock:
                    s.discard(ctx)
                ctx.cancel()
                if ctx.buf:
                    # This is usually not a good sign
                    log.warning("Task #%s with protocol %s has unprocessed "
                                "data before getting disconnected",
                                task_id, protocol)
        finally:
            task_log_stop(task_id)

    def negotiate_protocol(self, task_id, ctx):
        header = ctx.read_newline()
        if b" " in header:
            command, version = header.split()
            version = int(version)
        else:
            command, version = header, None
        klass = self.commands.get(command)
        if not klass:
            log.warning("Task #%s: unknown netlog protocol requested (%r), "
                        "terminating connection.", task_id, command)
            return
        ctx.command = command
        return klass(task_id, ctx, version)


class ResultServer(metaclass=Singleton):
    """Manager for the ResultServer worker and task state."""

    def __init__(self):
        ip = cfg.resultserver.ip
        port = cfg.resultserver.port
        pool_size = cfg.resultserver.pool_size

        sock = gevent.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind((ip, port))
        except (OSError, socket.error) as e:
            if e.errno == errno.EADDRINUSE:
                raise CuckooCriticalError(
                    "Cannot bind ResultServer on port %d "
                    "because it was in use, bailing." % port
                )
            elif e.errno == errno.EADDRNOTAVAIL:
                raise CuckooCriticalError(
                    "Unable to bind ResultServer on %s:%s %s. This "
                    "usually happens when you start Cuckoo without "
                    "bringing up the virtual interface associated with "
                    "the ResultServer IP address. Please refer to "
                    "https://cuckoo.sh/docs/faq/#troubles-problem "
                    "for more information." % (ip, port, e)
                )
            else:
                raise CuckooCriticalError(
                    "Unable to bind ResultServer on %s:%s: %s" %
                    (ip, port, e)
                )

        # We allow user to specify port 0 to get a random port, report it back
        # here
        _, self.port = sock.getsockname()
        sock.listen(128)

        self.thread = Thread(target=self.create_server, args=(sock, pool_size))
        self.thread.daemon = True
        self.thread.start()

    def add_task(self, task, machine):
        """Register a task/machine with the ResultServer."""
        self.instance.add_task(task.id, machine.ip)

    def del_task(self, task, machine):
        """Delete running task and cancel existing handlers."""
        self.instance.del_task(task.id, machine.ip)

    def create_server(self, sock, pool_size):
        if pool_size:
            pool = gevent.pool.Pool(pool_size)
        else:
            pool = 'default'
        self.instance = GeventResultServerWorker(sock, spawn=pool)
        self.instance.do_run()

