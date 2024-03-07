# Copyright (C) 2010-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import cgi
import enum
import http.server
import ipaddress
import json
import multiprocessing
import os
import platform
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import traceback
from io import StringIO
from typing import Iterable
from zipfile import ZipFile

try:
    import re2 as re
except ImportError:
    import re

if sys.version_info[:2] < (3, 6):
    sys.exit("You are running an incompatible version of Python, please use >= 3.6")

# You must run x86 version not x64
# The analysis process interacts with low-level Windows libraries that need a
# x86 Python to be running.
# (see https://github.com/kevoreilly/CAPEv2/issues/1680)
if sys.maxsize > 2**32 and sys.platform == "win32":
    sys.exit("You should install python3 x86! not x64")

AGENT_VERSION = "0.14"
AGENT_FEATURES = [
    "execpy",
    "execute",
    "pinning",
    "logs",
    "largefile",
    "unicodepath",
]


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


ANALYZER_FOLDER = ""
state = {
    "status": Status.INIT,
    "description": "",
}


class MiniHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "CAPE Agent"

    def do_GET(self):
        request.client_ip, request.client_port = self.client_address
        request.form = {}
        request.files = {}
        request.method = "GET"

        self.httpd.handle(self)

    def do_POST(self):
        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": self.headers.get("Content-Type"),
        }

        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=environ)

        request.client_ip, request.client_port = self.client_address
        request.form = {}
        request.files = {}
        request.method = "POST"

        if form.list:
            for key in form.keys():
                value = form[key]
                if value.filename:
                    request.files[key] = value.file
                else:
                    request.form[key] = value.value
        self.httpd.handle(self)


class MiniHTTPServer:
    def __init__(self):
        self.handler = MiniHTTPRequestHandler

        # Reference back to the server.
        self.handler.httpd = self

        self.routes = {
            "GET": [],
            "POST": [],
        }

    def run(
        self,
        host: ipaddress.IPv4Address = "0.0.0.0",
        port: int = 8000,
        event: multiprocessing.Event = None,
    ):
        socketserver.TCPServer.allow_reuse_address = True
        self.s = socketserver.TCPServer((host, port), self.handler)

        # tell anyone waiting that they're good to go
        if event:
            event.set()

        self.s.serve_forever()

    def route(self, path: str, methods: Iterable[str] = ["GET"]):
        def register(fn):
            for method in methods:
                self.routes[method].append((re.compile(f"{path}$"), fn))
            return fn

        return register

    def handle(self, obj):
        if "client_ip" in state and request.client_ip != state["client_ip"]:
            if request.client_ip != "127.0.0.1":
                return
            if obj.path != "/status" or request.method != "POST":
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
            ret.write(obj.wfile)

        if hasattr(self, "s") and self.s._BaseServer__shutdown_request:
            self.close_connection = True

    def shutdown(self):
        # BaseServer also features a .shutdown() method, but you can't use
        # that from the same thread as that will deadlock the whole thing.
        if hasattr(self, "s"):
            self.s._BaseServer__shutdown_request = True
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

    def json(self):
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

    def __init__(self, path):
        self.path = path
        self.status_code = 200

    def init(self):
        if os.path.isfile(self.path) and os.access(self.path, os.R_OK):
            self.length = os.path.getsize(self.path)
        else:
            self.status_code = 404
            self.length = 0

    def write(self, sock):
        if not self.length:
            return

        with open(self.path, "rb") as f:
            buf = f.read(1024 * 1024)
            while buf:
                sock.write(buf)
                buf = f.read(1024 * 1024)

    def headers(self, obj):
        obj.send_header("Content-Length", self.length)


class request:
    form = {}
    files = {}
    client_ip = None
    client_port = None
    method = None
    environ = {
        "werkzeug.server.shutdown": lambda: app.shutdown(),
    }


app = MiniHTTPServer()


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


def json_error(error_code: int, message: str) -> jsonify:
    r = jsonify(message=message, error_code=error_code)
    r.status_code = error_code
    return r


def json_exception(message: str) -> jsonify:
    r = jsonify(message=message, error_code=500, traceback=traceback.format_exc())
    r.status_code = 500
    return r


def json_success(message: str, **kwargs) -> jsonify:
    return jsonify(message=message, **kwargs)


@app.route("/")
def get_index():
    is_admin = isAdmin()
    return json_success("CAPE Agent!", version=AGENT_VERSION, features=AGENT_FEATURES, is_user_admin=bool(is_admin))


@app.route("/status")
def get_status():
    return json_success("Analysis status", status=str(state.get("status")), description=state.get("description"))


@app.route("/status", methods=["POST"])
def put_status():
    try:
        status = Status(request.form.get("status"))
    except ValueError:
        return json_error(400, "No valid status has been provided")

    state["status"] = status
    state["description"] = request.form.get("description")
    return json_success("Analysis status updated")


@app.route("/logs")
def get_logs():
    if isinstance(sys.stdout, StringIO):
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

    mode = int(request.form.get("mode", 0o777))

    try:
        os.makedirs(request.form["dirpath"], mode=mode)
    except Exception:
        return json_exception("Error creating directory")

    return json_success("Successfully created directory")


@app.route("/mktemp", methods=("GET", "POST"))
def do_mktemp():
    suffix = request.form.get("suffix", "")
    prefix = request.form.get("prefix", "tmp")
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
    prefix = request.form.get("prefix", "tmp")
    dirpath = request.form.get("dirpath")

    try:
        dirpath = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dirpath)
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
        with open(request.form["filepath"], "wb") as f:
            shutil.copyfileobj(request.files["file"], f, 10 * 1024 * 1024)
    except Exception:
        return json_exception("Error storing file")

    return json_success("Successfully stored file")


@app.route("/retrieve", methods=["POST"])
def do_retrieve():
    if "filepath" not in request.form:
        return json_error(400, "No filepath has been provided")

    return send_file(request.form["filepath"])


@app.route("/extract", methods=["POST"])
def do_extract():
    if "dirpath" not in request.form:
        return json_error(400, "No dirpath has been provided")

    if "zipfile" not in request.files:
        return json_error(400, "No zip file has been provided")

    try:
        with ZipFile(request.files["zipfile"], "r") as archive:
            archive.extractall(request.form["dirpath"])
    except Exception:
        return json_exception("Error extracting zip file")

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
            subprocess.Popen(request.form["command"], shell=shell, cwd=cwd)
        else:
            p = subprocess.Popen(request.form["command"], shell=shell, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
    except Exception:
        state["status"] = Status.FAILED
        state["description"] = "Error execute command"
        return json_exception("Error executing command")

    state["status"] = Status.RUNNING
    state["description"] = ""
    return json_success("Successfully executed command", stdout=stdout, stderr=stderr)


@app.route("/execpy", methods=["POST"])
def do_execpy():
    if "filepath" not in request.form:
        return json_error(400, "No Python file has been provided")

    # Execute the command asynchronously? As a shell command?
    async_exec = "async" in request.form

    cwd = request.form.get("cwd")
    stdout = stderr = None

    args = (
        sys.executable,
        request.form["filepath"],
    )

    try:
        if async_exec:
            subprocess.Popen(args, cwd=cwd)
        else:
            p = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
    except Exception:
        state["status"] = Status.FAILED
        state["description"] = "Error executing command"
        return json_exception("Error executing command")

    state["status"] = Status.RUNNING
    return json_success("Successfully executed command", stdout=stdout, stderr=stderr)


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
    multiprocessing.set_start_method("spawn")
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="0.0.0.0")
    parser.add_argument("port", type=int, nargs="?", default=8000)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not args.verbose:
        sys.stdout = StringIO()
        sys.stderr = StringIO()

    app.run(host=args.host, port=args.port)
