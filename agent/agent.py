# Copyright (C) 2010-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import base64
import contextlib
import enum
import http.server
import ipaddress
import json
import os
import platform
import random
import shlex
import shutil
import socket
import socketserver
import stat
import string
import subprocess
import sys
import tempfile
import time
import traceback
from email.message import EmailMessage
from email.parser import BytesHeaderParser
from email.policy import default as email_policy
from io import BufferedIOBase, BytesIO, StringIO
from threading import Lock
from typing import Any, Dict, IO, Iterable, Optional, Tuple, Union
from urllib.parse import parse_qs
from zipfile import ZipFile

try:
    import re2 as re  # type: ignore
except ImportError:
    import re

if sys.version_info[:2] < (3, 6):
    sys.exit("You are running an incompatible version of Python, please use >= 3.6")

# You must run x86 version not x64
# The analysis process interacts with low-level Windows libraries that need a
# x86 Python to be running.
# (see https://github.com/kevoreilly/CAPEv2/issues/1680)
#if sys.maxsize > 2**32 and sys.platform == "win32":
#    sys.exit("You should install python3 x86! not x64")

AGENT_VERSION = "0.24"
AGENT_FEATURES = [
    "execpy",
    "execute",
    "pinning",
    "logs",
    "largefile",
    "unicodepath",
    "subdir_upload",
]
BASE_64_ENCODING = "base64"

if sys.platform == "win32":
    AGENT_FEATURES.append("mutex")
    AGENT_FEATURES.append("browser_extension")
    MUTEX_TIMEOUT_MS = 500
    from ctypes import WinError, windll

    kernel32 = windll.kernel32
    SYNCHRONIZE = 0x100000
    ERROR_FILE_NOT_FOUND = 0x2
    WAIT_ABANDONED = 0x00000080
    WAIT_OBJECT_0 = 0x0
    WAIT_TIMEOUT = 0x102
    WAIT_FAILED = 0xFFFFFFFF


class Status(enum.IntEnum):
    INIT = 1
    RUNNING = 2
    COMPLETE = 3
    FAILED = 4
    EXCEPTION = 5

    def __str__(self):
        return f"{self.name.lower()}"

    @classmethod
    def _missing_(cls, value):
        if not isinstance(value, str):
            return None
        value = value.lower()
        for member in cls:
            if str(member) == value:
                return member
            if value.isnumeric() and int(value) == member.value:
                return member
        return None


TERMINAL_STATUSES = [Status.COMPLETE, Status.FAILED, Status.EXCEPTION]

AGENT_BROWSER_EXT_PATH = ""
AGENT_BROWSER_LOCK = Lock()
ANALYZER_FOLDER = ""
agent_mutexes: dict = {}
"""Holds handles of mutexes held by the agent."""
state: Dict[str, Any] = {
    "status": Status.INIT,
    "description": "",
    "async_subprocess": None,
    "mutexes": agent_mutexes,
}


_MULTIPART_CHUNK_SIZE = 1024 * 1024
_MULTIPART_MEMORY_LIMIT = 1024 * 1024
_MAX_PART_HEADER_BYTES = 64 * 1024


class _FormParseError(ValueError):
    """Raised when an HTTP request body has invalid form or multipart framing."""


class _BoundedReader:
    """Read at most *limit* bytes from an underlying binary stream."""

    def __init__(self, rfile: Union[BufferedIOBase, IO[bytes]], limit: int) -> None:
        self._rfile = rfile
        self.remaining = max(0, limit)

    def read(self, size: int = _MULTIPART_CHUNK_SIZE) -> bytes:
        if self.remaining <= 0:
            return b""
        to_read = self.remaining if size < 0 else min(size, self.remaining)
        if to_read <= 0:
            return b""
        data = self._rfile.read(to_read)
        if not data:
            self.remaining = 0
            return b""
        self.remaining -= len(data)
        return data

    def drain(self, chunk_size: int = _MULTIPART_CHUNK_SIZE) -> None:
        while self.remaining > 0:
            if not self.read(chunk_size):
                break


class _SpilledTempFile:
    """NamedTemporaryFile wrapper that supports zero-copy move_to() and unlinks on close()."""

    def __init__(self) -> None:
        self._fp: IO[bytes] = tempfile.NamedTemporaryFile("w+b", prefix="cape-part-", delete=False)
        self.name: str = self._fp.name
        self._moved = False

    @property
    def closed(self) -> bool:
        return self._fp.closed

    def write(self, data: Union[bytes, bytearray]) -> int:
        return self._fp.write(data)

    def read(self, size: int = -1) -> bytes:
        return self._fp.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._fp.seek(offset, whence)

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._fp.tell()

    def flush(self) -> None:
        self._fp.flush()

    def move_to(self, dest_path: str) -> None:
        self._fp.flush()
        self._fp.close()
        shutil.move(self.name, dest_path)
        self._moved = True

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._fp.close()
        if not self._moved and self.name:
            with contextlib.suppress(OSError):
                os.unlink(self.name)


class _PartFileSink:
    """Buffer small uploaded files in BytesIO and spill larger ones to a temporary file."""

    def __init__(self, max_mem_bytes: int = _MULTIPART_MEMORY_LIMIT) -> None:
        self._max_mem_bytes = max_mem_bytes
        self._buf: Any = BytesIO()
        self._size = 0
        self._spilled = False

    def write(self, data: Union[bytes, bytearray]) -> None:
        if not data:
            return
        next_size = self._size + len(data)
        if not self._spilled and next_size > self._max_mem_bytes:
            tmp: Any = _SpilledTempFile()
            self._buf.seek(0)
            shutil.copyfileobj(self._buf, tmp)
            self._buf.close()
            self._buf = tmp
            self._spilled = True
        self._buf.write(data)
        self._size = next_size

    def finish(self) -> IO[bytes]:
        self._buf.seek(0)
        return self._buf

    def close(self) -> None:
        self._buf.close()


def _parse_multipart_stream(
    reader: _BoundedReader,
    boundary_bytes: bytes,
    chunk_size: int = _MULTIPART_CHUNK_SIZE,
    spool_max_bytes: int = _MULTIPART_MEMORY_LIMIT,
) -> Tuple[Dict[str, str], Dict[str, IO[bytes]]]:
    """Stream-parse a multipart/form-data body without buffering whole files in RAM."""
    form: Dict[str, str] = {}
    files: Dict[str, IO[bytes]] = {}
    dash_boundary = b"--" + boundary_bytes
    buf = bytearray()
    skipped_preamble = False

    try:
        min_open = len(dash_boundary) + 4
        while len(buf) < min_open:
            chunk = reader.read(chunk_size)
            if not chunk:
                break
            buf.extend(chunk)

        nl = b"\r\n"
        while True:
            pos = -1
            if not skipped_preamble and buf.startswith(dash_boundary):
                pos = 0
            else:
                idx_crlf = buf.find(b"\r\n" + dash_boundary)
                idx_lf = buf.find(b"\n" + dash_boundary)
                candidates = [idx + 2 for idx in (idx_crlf,) if idx != -1] + [
                    idx + 1 for idx in (idx_lf,) if idx != -1 and (idx == 0 or buf[idx - 1] != 0x0D)
                ]
                if candidates:
                    pos = min(candidates)

            if pos != -1:
                after = pos + len(dash_boundary)
                while len(buf) < after + 4:
                    chunk = reader.read(chunk_size)
                    if not chunk:
                        break
                    buf.extend(chunk)
                ws_end = after
                while ws_end < len(buf) and buf[ws_end] in (0x20, 0x09):
                    ws_end += 1
                    if ws_end == len(buf):
                        chunk = reader.read(chunk_size)
                        if chunk:
                            buf.extend(chunk)
                if buf[after : after + 2] == b"--":
                    reader.drain(chunk_size)
                    return form, files
                if buf[ws_end : ws_end + 2] == b"\r\n":
                    nl = b"\r\n"
                    del buf[: ws_end + 2]
                    break
                if buf[ws_end : ws_end + 1] == b"\n":
                    nl = b"\n"
                    del buf[: ws_end + 1]
                    break
                del buf[: pos + 2]
                skipped_preamble = True
                continue

            keep = len(dash_boundary) + 2
            if len(buf) > keep:
                del buf[:-keep]
                skipped_preamble = True
            chunk = reader.read(chunk_size)
            if not chunk:
                raise _FormParseError("Missing multipart boundary")
            buf.extend(chunk)

        delimiter = nl + dash_boundary
        header_sep = nl + nl

        while True:
            while not buf.startswith(nl) and header_sep not in buf:
                if len(buf) > _MAX_PART_HEADER_BYTES:
                    raise _FormParseError("Multipart part headers exceed maximum size")
                chunk = reader.read(chunk_size)
                if not chunk:
                    raise _FormParseError("Incomplete multipart part headers")
                buf.extend(chunk)

            if buf.startswith(nl):
                header_bytes = b""
                del buf[: len(nl)]
            else:
                sep_idx = buf.index(header_sep)
                header_bytes = bytes(buf[:sep_idx])
                del buf[: sep_idx + len(header_sep)]

            part_msg = BytesHeaderParser(EmailMessage, policy=email_policy).parsebytes(header_bytes + b"\r\n\r\n")
            raw_name = part_msg.get_param("name", header="content-disposition")
            if isinstance(raw_name, tuple):
                name: Optional[str] = raw_name[2]
            elif isinstance(raw_name, str):
                name = raw_name
            else:
                name = None
            filename = part_msg.get_filename()
            charset = part_msg.get_content_charset("utf-8") or "utf-8"

            file_sink: Optional[_PartFileSink] = _PartFileSink(spool_max_bytes) if (name and filename) else None
            form_buf: Optional[bytearray] = bytearray() if (name and not filename) else None

            try:
                is_closing = False
                while True:
                    idx = buf.find(delimiter)
                    if idx != -1:
                        after_delim = idx + len(delimiter)
                        while len(buf) < after_delim + 4:
                            chunk = reader.read(chunk_size)
                            if not chunk:
                                break
                            buf.extend(chunk)
                        ws_end = after_delim
                        while ws_end < len(buf) and buf[ws_end] in (0x20, 0x09):
                            ws_end += 1
                            if ws_end == len(buf):
                                chunk = reader.read(chunk_size)
                                if chunk:
                                    buf.extend(chunk)
                        if buf[after_delim : after_delim + 2] == b"--":
                            if idx > 0:
                                if file_sink is not None:
                                    file_sink.write(buf[:idx])
                                elif form_buf is not None:
                                    form_buf.extend(buf[:idx])
                            del buf[: after_delim + 2]
                            is_closing = True
                            break
                        if buf[ws_end : ws_end + 2] == b"\r\n":
                            if idx > 0:
                                if file_sink is not None:
                                    file_sink.write(buf[:idx])
                                elif form_buf is not None:
                                    form_buf.extend(buf[:idx])
                            del buf[: ws_end + 2]
                            is_closing = False
                            break
                        if buf[ws_end : ws_end + 1] == b"\n":
                            if idx > 0:
                                if file_sink is not None:
                                    file_sink.write(buf[:idx])
                                elif form_buf is not None:
                                    form_buf.extend(buf[:idx])
                            del buf[: ws_end + 1]
                            is_closing = False
                            break
                        # False boundary prefix inside binary payload; flush past the leading newline.
                        if file_sink is not None:
                            file_sink.write(buf[: idx + 1])
                        elif form_buf is not None:
                            form_buf.extend(buf[: idx + 1])
                        del buf[: idx + 1]
                        continue

                    safe_len = len(buf) - (len(delimiter) - 1)
                    if safe_len > 0:
                        if file_sink is not None:
                            file_sink.write(buf[:safe_len])
                        elif form_buf is not None:
                            form_buf.extend(buf[:safe_len])
                        del buf[:safe_len]
                    chunk = reader.read(chunk_size)
                    if not chunk:
                        raise _FormParseError("Incomplete multipart/form-data body")
                    buf.extend(chunk)

                if name:
                    if file_sink is not None:
                        if name in files:
                            files[name].close()
                        files[name] = file_sink.finish()
                        file_sink = None
                    elif form_buf is not None:
                        try:
                            form[name] = form_buf.decode(charset, errors="replace")
                        except LookupError:
                            form[name] = form_buf.decode("utf-8", errors="replace")
            finally:
                if file_sink is not None:
                    file_sink.close()

            if is_closing:
                reader.drain(chunk_size)
                break
    except Exception:
        for file_obj in files.values():
            try:
                file_obj.close()
            except Exception:
                pass
        raise

    return form, files


class MiniHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "CAPE Agent"
    httpd: "MiniHTTPServer"
    multipart_chunk_size: int = _MULTIPART_CHUNK_SIZE
    multipart_memory_limit: int = _MULTIPART_MEMORY_LIMIT

    @staticmethod
    def _close_files(files: Dict[str, IO[bytes]]) -> None:
        for file_obj in files.values():
            try:
                file_obj.close()
            except Exception:
                pass

    def _send_json_response(self, ret: "jsonify") -> None:
        try:
            ret.init()
            self.send_response(ret.status_code)
            ret.headers(self)
            self.end_headers()
            self.wfile.write(ret.json().encode())
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _parse_form_and_files(self) -> Tuple[Dict[str, str], Dict[str, IO[bytes]]]:
        try:
            content_length = max(0, int(self.headers.get("Content-Length", "0") or 0))
        except ValueError as exc:
            raise _FormParseError("Invalid Content-Length header") from exc

        content_type = self.headers.get("Content-Type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()

        if media_type == "multipart/form-data":
            if content_length <= 0:
                return {}, {}
            ct_msg = BytesHeaderParser(EmailMessage, policy=email_policy).parsebytes(
                b"Content-Type: " + content_type.encode("utf-8", errors="surrogateescape") + b"\r\n\r\n"
            )
            raw_boundary = ct_msg.get_param("boundary")
            if isinstance(raw_boundary, tuple):
                boundary_str: Optional[str] = raw_boundary[2]
            elif isinstance(raw_boundary, str):
                boundary_str = raw_boundary
            else:
                boundary_str = None
            if not boundary_str:
                raise _FormParseError("Missing boundary in multipart/form-data Content-Type")
            boundary_bytes = boundary_str.encode("utf-8", errors="surrogateescape")
            reader = _BoundedReader(self.rfile, content_length)
            return _parse_multipart_stream(
                reader,
                boundary_bytes,
                chunk_size=self.multipart_chunk_size,
                spool_max_bytes=self.multipart_memory_limit,
            )

        body = self.rfile.read(content_length) if content_length > 0 else b""
        form: Dict[str, str] = {}
        files: Dict[str, IO[bytes]] = {}
        if media_type == "application/x-www-form-urlencoded":
            # Match cgi.FieldStorage default behavior: ignore blank form values.
            parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=False)
            form = {k: v[-1] if v else "" for k, v in parsed.items()}

        return form, files

    def do_GET(self):
        request.client_ip, request.client_port = self.client_address
        request.form = {}
        request.files = {}
        request.method = "GET"

        self.httpd.handle(self)

    def do_POST(self):
        request.client_ip, request.client_port = self.client_address
        request.form = {}
        request.files = {}
        request.method = "POST"
        if not self.httpd.is_client_allowed(self.path, request.method):
            return
        try:
            request.form, request.files = self._parse_form_and_files()
        except _FormParseError as exc:
            self._send_json_response(json_error(400, f"Invalid form data: {exc}"))
            return

        try:
            self.httpd.handle(self)
        finally:
            self._close_files(request.files)
            request.files = {}

    def do_DELETE(self):
        request.client_ip, request.client_port = self.client_address
        request.form = {}
        request.files = {}
        request.method = "DELETE"
        if not self.httpd.is_client_allowed(self.path, request.method):
            return
        try:
            request.form, request.files = self._parse_form_and_files()
        except _FormParseError as exc:
            self._send_json_response(json_error(400, f"Invalid form data: {exc}"))
            return

        try:
            self.httpd.handle(self)
        finally:
            self._close_files(request.files)
            request.files = {}


class MiniHTTPServer:
    def __init__(self):
        self.handler = MiniHTTPRequestHandler

        # Reference back to the server.
        self.handler.httpd = self

        self.routes = {
            "GET": [],
            "POST": [],
            "DELETE": [],
        }

    def run(
        self,
        host: ipaddress.IPv4Address = ipaddress.IPv4Address("0.0.0.0"),
        port: int = 8000,
        event = None,
    ):
        self.handler.httpd = self
        request.environ["werkzeug.server.shutdown"] = self.shutdown
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.s = socketserver.ThreadingTCPServer((str(host), port), self.handler)

        # tell anyone waiting that they're good to go
        if event:
            event.set()

        try:
            self.s.serve_forever()
        finally:
            self.s.server_close()

    def route(self, path: str, methods: Iterable[str] = ["GET"]):
        def register(fn):
            for method in methods:
                self.routes[method].append((re.compile(f"{path}$"), fn))
            return fn

        return register

    @staticmethod
    def is_client_allowed(path: str, method: Optional[str]) -> bool:
        if "client_ip" in state and request.client_ip != state["client_ip"]:
            if request.client_ip != "127.0.0.1":
                return False
            if path not in ["/status", "/browser_extension"] or method != "POST":
                return False
        return True

    def handle(self, obj):
        if not self.is_client_allowed(obj.path, request.method):
            return

        for route, fn in self.routes[obj.command]:
            if route.match(obj.path):
                ret = fn()
                break
        else:
            ret = json_error(404, message="Route not found")

        ret.init()
        obj.send_response(ret.status_code)
        ret.headers(obj)
        obj.end_headers()

        if isinstance(ret, jsonify):
            obj.wfile.write(ret.json().encode())
        elif isinstance(ret, send_file):
            ret.write(obj, obj.wfile)

        if hasattr(self, "s") and getattr(self.s, "_BaseServer__shutdown_request", False):
            self.close_connection = True

    def shutdown(self):
        # BaseServer also features a .shutdown() method, but you can't use
        # that from the same thread as that will deadlock the whole thing.
        if hasattr(self, "s"):
            setattr(self.s, "_BaseServer__shutdown_request", True)
        else:
            # When running unit tests in Windows, the system would hang here,
            # until this `exit(1)` was added.
            print(f"{self} has no 's' attribute")
            exit(1)


class jsonify:
    """Wrapper that represents Flask.jsonify functionality."""

    def __init__(self, status_code=200, **kwargs):
        self.status_code = status_code
        self.values = kwargs

    def init(self):
        pass

    def json(self) -> str:
        for valkey in self.values:
            if isinstance(self.values[valkey], bytes):
                self.values[valkey] = self.values[valkey].decode("utf8", "replace")
        try:
            retdata = json.dumps(self.values)
        except Exception as ex:
            retdata = json.dumps({"error": f"Error serializing json data: {ex.args[0]}"})

        return retdata

    def headers(self, obj):
        pass


class send_file:
    """Wrapper that represents Flask.send_file functionality."""

    def __init__(self, path, encoding, streaming):
        self.length = None
        self.path = path
        self.status_code = 200
        self.encoding = encoding
        self.streaming = False
        if streaming == "1":
            self.streaming = True

    def okay_to_send(self):
        return os.path.isfile(self.path) and os.access(self.path, os.R_OK)

    def init(self):
        if self.okay_to_send():
            if self.encoding != BASE_64_ENCODING and not self.streaming:
                self.length = os.path.getsize(self.path)
        else:
            self.status_code = 404

    def write_streaming(self, httplog, sock):
        """Streaming output. similar to using 'tail -f <file>"""

        with open(self.path, "rb") as f:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                try:
                    sock.write(line)
                except (BrokenPipeError, ConnectionResetError):
                    httplog.log_message(f"Client disconnected while reading {self.path}")
                    break

    def write(self, httplog, sock):
        if not self.okay_to_send():
            return

        if self.streaming:
            self.write_streaming(httplog, sock)
            return
        try:
            with open(self.path, "rb") as f:
                buf = f.read(1024 * 1024)
                while buf:
                    if self.encoding == BASE_64_ENCODING:
                        buf = base64.b64encode(buf)
                    sock.write(buf)
                    buf = f.read(1024 * 1024)
        except Exception as ex:
            httplog.log_error(f"Error reading file {self.path}: {ex}")

    def headers(self, obj):
        if self.length is not None:
            obj.send_header("Content-Length", self.length)


class request:
    form: dict = {}
    files: dict = {}
    client_ip = None
    client_port = None
    method = None
    environ = {
        "werkzeug.server.shutdown": lambda: app.shutdown(),
    }


app: MiniHTTPServer = MiniHTTPServer()


def isAdmin():
    is_admin = None
    try:
        if sys.platform == "win32":
            import ctypes

            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.getuid() == 0
    except Exception as e:
        print(e)

    return is_admin


def json_error(error_code: int, message: str, **kwargs) -> jsonify:
    r = jsonify(message=message, error_code=error_code, **kwargs)
    r.status_code = error_code
    return r


def json_exception(message: str) -> jsonify:
    r = jsonify(message=message, error_code=500, traceback=traceback.format_exc())
    r.status_code = 500
    return r


def json_success(message: str, status_code=200, **kwargs) -> jsonify:
    return jsonify(message=message, status_code=status_code, **kwargs)


@app.route("/")
def get_index():
    is_admin = isAdmin()
    return json_success("CAPE Agent!", version=AGENT_VERSION, features=AGENT_FEATURES, is_user_admin=bool(is_admin))


def get_subprocess_status():
    """Return the subprocess status."""
    async_subprocess = state.get("async_subprocess")
    message = "Analysis status"
    if async_subprocess is None:
        return json_success(message=message, status=str(state.get("status")), description=state.get("description"))
    exitcode = async_subprocess.poll()
    if exitcode is None or (sys.platform == "win32" and exitcode == 259):
        # Process is still running.
        state["status"] = Status.RUNNING
        return json_success(
            message=message,
            status=str(state.get("status")),
            description=state.get("description"),
            process_id=async_subprocess.pid,
        )
    # Process completed; reset async subprocess state.
    state["async_subprocess"] = None
    if exitcode == 0:
        state["status"] = Status.COMPLETE
        state["description"] = ""
    else:
        state["status"] = Status.FAILED
        state["description"] = f"Exited with exit code {exitcode}"
    return json_success(
        message=message,
        status=str(state.get("status")),
        description=state.get("description"),
        exitcode=exitcode,
    )


def open_mutex(mutex_name):
    assert sys.platform == "win32"
    access = SYNCHRONIZE  # only flag the mutex for use
    inherit_handle = False  # don't pass the handle to children
    hndl_mutex = kernel32.OpenMutexW(access, inherit_handle, mutex_name)
    if not hndl_mutex:
        winerr = WinError()
        if winerr.errno == ERROR_FILE_NOT_FOUND:
            return None, json_error(404, "mutex not found")
        return None, json_error(500, f"error accessing mutex: {winerr}")
    return hndl_mutex, None


def wait_mutex(hndl_mutex):
    assert sys.platform == "win32"
    ret = kernel32.WaitForSingleObject(hndl_mutex, MUTEX_TIMEOUT_MS)
    if ret in (WAIT_ABANDONED, WAIT_OBJECT_0):
        return True, None
    elif ret == WAIT_TIMEOUT:
        return False, json_error(408, "timeout waiting for mutex")
    elif ret == WAIT_FAILED:
        # get the extended error information
        winerr = WinError()
        return False, json_error(500, f"failed waiting for mutex: {winerr}")
    else:
        return False, json_error(500, f"failed waiting for mutex: {ret}")


def release_mutex(hndl_mutex):
    assert sys.platform == "win32"
    ret = kernel32.ReleaseMutex(hndl_mutex)
    if not ret:
        # get the extended error information
        winerr = WinError()
        return False, json_error(500, f"failed releasing mutex: {winerr}")
    return True, None


@app.route("/status")
def get_status():
    if state["status"] != Status.COMPLETE and state.get("async_subprocess") is not None:
        return get_subprocess_status()
    return json_success("Analysis status", status=str(state.get("status")), description=state.get("description"))


@app.route("/mutex", methods=["POST"])
def post_mutex():
    if sys.platform != "win32":
        return json_error(400, f"mutex feature not supported on {sys.platform}")
    mutex_name = request.form.get("mutex", "")
    if not mutex_name:
        return json_error(400, "no mutex provided")
    if mutex_name in agent_mutexes:
        return json_success(f"have mutex: {mutex_name}")

    # does the mutex exist?
    hndl_mutex, error = open_mutex(mutex_name)
    if error:
        return error

    # try waiting on it
    ok, error = wait_mutex(hndl_mutex)
    if ok:
        # save the mutex handle for future requests
        agent_mutexes[mutex_name] = hndl_mutex
        return json_success(f"got mutex: {mutex_name}", status_code=201)
    return error


@app.route("/mutex", methods=["DELETE"])
def delete_mutex():
    if sys.platform != "win32":
        return json_error(400, f"mutex feature not supported on {sys.platform}")
    mutex_name = request.form.get("mutex", "")
    if not mutex_name:
        return json_error(400, "no mutex provided")
    if mutex_name not in agent_mutexes:
        return json_error(404, f"mutex does not exist: {mutex_name}")
    hndl_mutex = agent_mutexes.pop(mutex_name)
    ok, error = release_mutex(hndl_mutex)
    if ok:
        return json_success(f"released mutex: {mutex_name}")
    return error


@app.route("/status", methods=["POST"])
def put_status():
    try:
        status = Status(request.form.get("status"))
    except ValueError:
        return json_error(400, "No valid status has been provided")

    # If the new status is terminal, unset the async subprocess so /status reports
    # the final analysis state rather than the child process state.
    if status in TERMINAL_STATUSES:
        state["async_subprocess"] = None

    state["status"] = status
    state["description"] = request.form.get("description")
    return json_success("Analysis status updated")


@app.route("/logs")
def get_logs():
    if isinstance(sys.stdout, StringIO) and isinstance(sys.stderr, StringIO):
        stdoutbuf = sys.stdout.getvalue()
        stderrbuf = sys.stderr.getvalue()
    else:
        stdoutbuf = "verbose mode, stdout not saved"
        stderrbuf = "verbose mode, stderr not saved"
    return json_success("Agent logs", stdout=stdoutbuf, stderr=stderrbuf)


@app.route("/system")
def get_system():
    return json_success("System", system=platform.system())


@app.route("/environ")
def get_environ():
    return json_success("Environment variables", environ=dict(os.environ))


@app.route("/path")
def get_path():
    return json_success("Agent path", filepath=os.path.abspath(__file__))


@app.route("/mkdir", methods=["POST"])
def do_mkdir():
    if "dirpath" not in request.form:
        return json_error(400, "No dirpath has been provided")

    try:
        mode = int(request.form.get("mode", 0o777))

        os.makedirs(request.form["dirpath"], mode=mode, exist_ok=True)
    except Exception as ex:
        print(f"error creating dir {ex}")
        return json_exception("Error creating directory")

    return json_success("Successfully created directory")


@app.route("/mktemp", methods=("GET", "POST"))
def do_mktemp():
    suffix = request.form.get("suffix", "")
    prefix = request.form.get("prefix", "")
    dirpath = request.form.get("dirpath")

    try:
        fd, filepath = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dirpath)
    except Exception:
        return json_exception("Error creating temporary file")

    os.close(fd)

    return json_success("Successfully created temporary file", filepath=filepath)


@app.route("/mkdtemp", methods=("GET", "POST"))
def do_mkdtemp():
    suffix = request.form.get("suffix", "")
    prefix = request.form.get("prefix", "")
    dirpath = request.form.get("dirpath")

    try:
        dirpath = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dirpath)
        if sys.platform == "win32":
            subprocess.call(["icacls", dirpath, "/inheritance:e", "/grant", "*S-1-5-32-545:(OI)(CI)(RX)"])
    except Exception:
        return json_exception("Error creating temporary directory")

    return json_success("Successfully created temporary directory", dirpath=dirpath)


@app.route("/store", methods=["POST"])
def do_store():
    if "filepath" not in request.form:
        return json_error(400, "No filepath has been provided")

    if "file" not in request.files:
        return json_error(400, "No file has been provided")

    try:
        filepath = request.form["filepath"]
        dirpath = os.path.dirname(filepath)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)
        uploaded = request.files["file"]
        move_to = getattr(uploaded, "move_to", None)
        if callable(move_to):
            move_to(filepath)
        else:
            with open(filepath, "wb") as f:
                shutil.copyfileobj(uploaded, f, 10 * 1024 * 1024)
    except Exception as ex:
        return json_exception(f"Error storing file: {ex}")

    return json_success("Successfully stored file")


@app.route("/retrieve", methods=["POST"])
def do_retrieve():
    if "filepath" not in request.form:
        return json_error(400, "No filepath has been provided")

    return send_file(request.form["filepath"], request.form.get("encoding", ""), request.form.get("streaming", ""))


@app.route("/extract", methods=["POST"])
def do_extract():
    if "dirpath" not in request.form:
        return json_error(400, "No dirpath has been provided")

    if "zipfile" not in request.files:
        return json_error(400, "No zip file has been provided")

    try:
        with ZipFile(request.files["zipfile"], "r") as archive:
            archive.extractall(request.form["dirpath"])
    except Exception as ex:
        return json_exception(f"Error extracting zip file {ex}")

    return json_success("Successfully extracted zip file")


@app.route("/remove", methods=["POST"])
def do_remove():
    if "path" not in request.form:
        return json_error(400, "No path has been provided")

    try:
        if os.path.isdir(request.form["path"]):
            # Mark all files as readable so they can be deleted.
            for dirpath, _, filenames in os.walk(request.form["path"]):
                for filename in filenames:
                    os.chmod(os.path.join(dirpath, filename), stat.S_IWRITE)

            shutil.rmtree(request.form["path"])
            message = "Successfully deleted directory"
        elif os.path.isfile(request.form["path"]):
            os.chmod(request.form["path"], stat.S_IWRITE)
            os.remove(request.form["path"])
            message = "Successfully deleted file"
        else:
            return json_error(404, "Path provided does not exist")
    except Exception:
        return json_exception("Error removing file or directory")

    return json_success(message)


@app.route("/execute", methods=["POST"])
def do_execute():
    local_ip = socket.gethostbyname(socket.gethostname())

    if "command" not in request.form:
        return json_error(400, "No command has been provided")
    command_to_execute = shlex.split(request.form["command"])

    # only allow date command from localhost. Even this is just to
    # let it be tested
    allowed_commands = ["date", "cmd /c date /t"]
    if request.client_ip in ("127.0.0.1", local_ip) and request.form["command"] not in allowed_commands:
        return json_error(500, "Not allowed to execute commands")

    # Execute the command asynchronously? As a shell command?
    async_exec = "async" in request.form
    shell = "shell" in request.form

    cwd = request.form.get("cwd")
    stdout = stderr = None

    try:
        if async_exec:
            subprocess.Popen(command_to_execute, shell=shell, cwd=cwd)
        else:
            p = subprocess.Popen(command_to_execute, shell=shell, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            if request.form.get("encoding", "") == BASE_64_ENCODING:
                stdout = base64.b64encode(stdout)
                stderr = base64.b64encode(stderr)
    except Exception as ex:
        state["status"] = Status.FAILED
        state["description"] = "Error execute command"
        return json_exception(f"Error executing command: {ex}")

    state["status"] = Status.RUNNING
    state["description"] = ""
    return json_success("Successfully executed command", stdout=stdout, stderr=stderr)


def run_subprocess(command_args, cwd, base64_encode, shell=False):
    """Execute the subprocess, wait for completion.

    Return the exitcode (returncode), the stdout, and the stderr.
    """
    p = subprocess.Popen(
        args=command_args,
        cwd=cwd,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = p.communicate()
    if base64_encode:
        stdout = base64.b64encode(stdout)
        stderr = base64.b64encode(stderr)
    return p.returncode, stdout, stderr


def background_subprocess(command_args, cwd, base64_encode, shell=False):
    """Run subprocess, wait for completion, then exit.

    This process must exit, so the parent process (agent) can find the exit status."""
    # TODO: return the stdout/stderr to the parent process.
    returncode, stdout, stderr = run_subprocess(command_args, cwd, base64_encode, shell)
    sys.stdout.write(stdout.decode("ascii"))
    sys.stderr.write(stderr.decode("ascii"))
    sys.exit(returncode)


def spawn(args, cwd, base64_encode, shell=False):
    """Kick off a subprocess in the background."""
    proc = subprocess.Popen(args, cwd=cwd, shell=shell)
    state["status"] = Status.RUNNING
    state["description"] = ""
    state["async_subprocess"] = proc
    return json_success("Successfully spawned command", process_id=proc.pid)


@app.route("/execpy", methods=["POST"])
def do_execpy():
    if "filepath" not in request.form:
        return json_error(400, "No Python file has been provided")

    # Execute the command asynchronously? As a shell command?
    async_exec = "async" in request.form
    base64_encode = request.form.get("encoding", "") == BASE_64_ENCODING

    cwd = request.form.get("cwd")

    args = (
        sys.executable,
        request.form["filepath"],
    )

    if async_exec and state["status"] == Status.RUNNING and state["async_subprocess"]:
        return json_error(400, "Async process already running.")
    try:
        if async_exec:
            return spawn(args, cwd, base64_encode)
        exitcode, stdout, stderr = run_subprocess(args, cwd, base64_encode)
        if exitcode == 0:
            state["status"] = Status.COMPLETE
            state["description"] = ""
            return json_success("Successfully executed command", stdout=stdout, stderr=stderr)
        # Process exited with non-zero result.
        state["status"] = Status.FAILED
        message = "Error executing python command."
        state["description"] = message
        return json_error(400, message, stdout=stdout, stderr=stderr, exitcode=exitcode)
    except Exception as ex:
        state["status"] = Status.FAILED
        state["description"] = "Error executing Python command"
        return json_exception(f"Error executing Python command: {ex}")


def write_file_atomic(path: str, data: str, attempts: int = 5):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as tmp_fd:
        tmp_fd.write(data)
    for attempt in range(attempts):
        try:
            os.replace(tmp_path, path)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05)


@app.route("/browser_extension", methods=["POST"])
def do_browser_ext():
    global AGENT_BROWSER_EXT_PATH
    network_data = request.form.get("networkData")
    with AGENT_BROWSER_LOCK:
        if not AGENT_BROWSER_EXT_PATH or not os.path.isdir(os.path.dirname(AGENT_BROWSER_EXT_PATH)):
            try:
                ext_tmpdir = tempfile.mkdtemp(prefix="")
            except Exception:
                return json_exception("Error creating temporary directory")
            ext_filepath = "bext_" + "".join(random.choice(string.ascii_letters) for _ in range(11)) + ".json"
            AGENT_BROWSER_EXT_PATH = os.path.join(ext_tmpdir, ext_filepath)
        if network_data:
            try:
                write_file_atomic(AGENT_BROWSER_EXT_PATH, network_data)
            except Exception:
                return json_exception("Error writing the browser extension log")
    return json_success("OK")


@app.route("/pinning")
def do_pinning():
    if "client_ip" in state:
        return json_error(500, "Agent has already been pinned to an IP!")

    state["client_ip"] = request.client_ip
    return json_success("Successfully pinned Agent", client_ip=request.client_ip)


@app.route("/kill")
def do_kill():
    shutdown = request.environ.get("werkzeug.server.shutdown")
    if shutdown is None:
        return json_error(500, "Not running with the Werkzeug server")

    shutdown()
    return json_success("Quit the CAPE Agent")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="0.0.0.0")
    parser.add_argument("port", type=int, nargs="?", default=8000)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not args.verbose:
        sys.stdout = StringIO()
        sys.stderr = StringIO()

    app.run(host=args.host, port=args.port)
