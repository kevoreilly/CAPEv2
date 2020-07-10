# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import logging
import socket
import time

from lib.core.config import Config

log = logging.getLogger(__name__)

BUFSIZE = 1024 * 1024


def upload_to_host(file_path, dump_path, pids=[], metadata="", category=""):
    nc = infd = None
    if not os.path.exists(file_path):
        log.warning("File not exist: {}".format(file_path))
        return

    try:
        nc = NetlogFile()
        # nc = NetlogBinary(file_path.encode("utf-8", "replace"), dump_path, duplicate)
        nc.init(dump_path, file_path, pids, metadata, category)
        infd = open(file_path, "rb")  # rb
        buf = infd.read(BUFSIZE)
        log.info("Uploading file {} to host -> {}".format(file_path, dump_path))
        while buf:
            nc.send(buf, retry=True)
            buf = infd.read(BUFSIZE)
    except Exception as e:
        log.error("Exception uploading file {0} to host: {1}".format(file_path, e), exc_info=True)
    finally:
        if infd:
            infd.close()
        if nc:
            nc.close()


class NetlogConnection(object):
    def __init__(self, proto=""):
        config = Config(cfg="analysis.conf")
        self.hostip, self.hostport = config.ip, config.port
        self.sock = None
        self.proto = proto
        self.connected = False

    def connect(self):
        # Try to connect as quickly as possible. Just sort of force it to
        # connect with a short timeout.
        while not self.sock:
            try:
                s = socket.create_connection((self.hostip, self.hostport), 0.1)
            except socket.error:
                time.sleep(0.1)
                continue

            self.sock = s
            self.sock.settimeout(None)
            self.sock.sendall(self.proto)
            self.connected = True

    def send(self, data, retry=True):
        if not self.sock:
            self.connect()

        try:
            self.sock.sendall(data)
        except socket.error as e:
            if retry:
                self.connect()
                self.send(data, retry=False)
            else:
                print(("Unhandled exception in NetlogConnection:", str(e)))
        except Exception as e:
            log.error(("Unhandled exception in NetlogConnection:", str(e)))
            # We really have nowhere to log this, if the netlog connection
            # does not work, we can assume that any logging won't work either.
            # So we just fail silently.
            self.close()

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            self.sock = None
        except Exception as e:
            print(e)
            pass


class NetlogBinary(NetlogConnection):
    def __init__(self, guest_path, uploaded_path, duplicated):
        if duplicated:
            NetlogConnection.__init__(self, proto=b"DUPLICATEBINARY\n%s\n%s\n" % (uploaded_path.encode("utf-8", "replace"), guest_path))
        else:
            NetlogConnection.__init__(self, proto=b"BINARY\n%s\n%s\n" % (uploaded_path.encode("utf-8", "replace"), guest_path))
        self.connect()


class NetlogFile(NetlogConnection):
    def init(self, dump_path, filepath=False, pids="", metadata="", category="files"):
        """
            All arguments should be strings
        """
        if pids:
            pids = " ".join(pids)
        else:
            pids = ""
        if filepath:
            self.proto = b"FILE 2\n%s\n%s\n%s\n%s\n%s\n" % (
                dump_path.encode("utf8"),
                filepath.encode("utf-8", "replace"),
                pids.encode("utf8") if isinstance(pids, str) else pids,
                metadata.encode("utf8") if isinstance(metadata, str) else metadata,
                category.encode("utf8") if isinstance(category, str) else category,
            )
        else:
            self.proto = b"FILE\n%s\n" % dump_path.encode("utf8")
        self.connect()


class NetlogHandler(logging.Handler, NetlogConnection):
    def __init__(self):
        logging.Handler.__init__(self)
        NetlogConnection.__init__(self, proto=b"LOG\n")
        self.connect()

    def emit(self, record):
        msg = self.format(record)
        self.send(msg.encode("utf-8") + b"\n")
