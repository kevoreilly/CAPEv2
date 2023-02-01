# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import socket
import time
from pathlib import Path

from lib.common.parse_pe import is_pe_image, pe_trimmed_size
from lib.core.config import Config

config = Config(cfg="analysis.conf")

log = logging.getLogger(__name__)

BUFSIZE = 1024 * 1024


def get_upload_size(path):
    size = Path(path).stat().st_size
    if int(config.upload_max_size) < size and not config.do_upload_max_size:
        if config.enable_trim and is_pe_image(path):
            new_size = pe_trimmed_size(path)
            if new_size:
                size = new_size
                if int(config.upload_max_size) < size and not config.do_upload_max_size:
                    log.warning("PE File %s size is too big: %d, trim failed to bring size down", path, size)
                    return
            else:
                log.warning("PE File %s size is too big: %d, trim failed - check pefile is installed in guest", path, size)
                return
        else:
            log.warning("File %s size is too big: %d, ignoring", path, size)
            return
    return size


def upload_to_host(file_path, dump_path, pids="", ppids="", metadata="", category="", duplicated=False):
    if not os.path.exists(file_path):
        log.warning("File %s doesn't exist anymore", file_path)
        return

    size = get_upload_size(file_path)
    if not size:
        return

    log.info("Uploading file %s to %s; Size is %d; Max size: %s", file_path, dump_path, size, config.upload_max_size)
    nc = None
    try:
        nc = NetlogFile()
        nc.init(dump_path, file_path, pids, ppids, metadata, category, duplicated)
        if not duplicated and file_path:
            with open(file_path, "rb") as infd:
                buf = infd.read(BUFSIZE)
                while buf:
                    read_size = len(buf)
                    nc.send(buf[:size], retry=True)
                    if read_size > size:
                        break
                    size -= read_size
                    buf = infd.read(BUFSIZE)
    except Exception as e:
        log.error("Exception uploading file %s to host: %s", file_path, e, exc_info=True)
    finally:
        if nc:
            nc.close()


class NetlogConnection:
    def __init__(self, proto=""):
        self.hostip, self.hostport = config.ip, config.port
        self.sock = None
        self.proto = proto
        self.connected = False

    def connect(self):
        # Try to connect as quickly as possible. Just sort of force it to connect with a short timeout.
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
                print(f"Unhandled exception in NetlogConnection: {e}")
        except Exception as e:
            log.error("Unhandled exception in NetlogConnection: %s", e)
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


class NetlogBinary(NetlogConnection):
    def __init__(self, guest_path, uploaded_path, duplicated):
        if duplicated:
            NetlogConnection.__init__(
                self, proto=b"DUPLICATEBINARY\n%s\n%s\n" % (uploaded_path.encode("utf-8", "replace"), guest_path)
            )
        else:
            NetlogConnection.__init__(self, proto=b"BINARY\n%s\n%s\n" % (uploaded_path.encode("utf-8", "replace"), guest_path))
        self.connect()


class NetlogFile(NetlogConnection):
    def init(self, dump_path, filepath=False, pids="", ppids="", metadata="", category="files", duplicated=0):
        """
        All arguments should be strings
        """
        if not isinstance(pids, str):
            pids = " ".join(pids)
        if not isinstance(ppids, str):
            ppids = " ".join(ppids)
        if filepath:
            self.proto = b"FILE 2\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n" % (
                dump_path.encode(),
                filepath.encode("utf-8", "replace"),
                pids.encode(),
                ppids.encode(),
                metadata.encode() if isinstance(metadata, str) else metadata,
                category.encode() if isinstance(category, str) else category,
                1 if duplicated else 0,
            )
        else:
            self.proto = b"FILE\n%s\n" % dump_path.encode()
        self.connect()


class NetlogHandler(logging.Handler, NetlogConnection):
    def __init__(self):
        logging.Handler.__init__(self)
        NetlogConnection.__init__(self, proto=b"LOG\n")
        self.connect()

    def emit(self, record):
        msg = self.format(record)
        self.send(msg.encode() + b"\n")
