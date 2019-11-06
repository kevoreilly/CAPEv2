# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import re
import cgi
import sys
import json
import stat
import time
import shutil
import string
import random
import traceback
import platform
import tempfile
import argparse
import subprocess
import configparser
from io import BytesIO
from zipfile import ZipFile

import http.server
import socketserver

AGENT_VERSION = "0.10"
AGENT_FEATURES = [
    "execpy", "pinning", "logs", "largefile", "unicodepath",
]

STATUS_INIT = 0x0001
STATUS_RUNNING = 0x0002
STATUS_COMPLETED = 0x0003
STATUS_FAILED = 0x0004
CURRENT_STATUS = STATUS_INIT

ERROR_MESSAGE = ""
ANALYZER_FOLDER = ""
COMPLETION_KEY = ""

#sys.stdout = BytesIO()
#sys.stderr = BytesIO()

class Agent:
    """Cuckoo agent, it runs inside guest."""

    def __init__(self):
        self.system = platform.system().lower()
        self.analyzer_path = ""
        self.analyzer_pid = 0

    def _initialize(self):
        global ERROR_MESSAGE
        global ANALYZER_FOLDER
        global COMPLETION_KEY

        if not ANALYZER_FOLDER:
            random.seed(time.time())
            container = "".join(random.choice(string.ascii_lowercase) for x in range(random.randint(5, 10)))
            COMPLETION_KEY = "".join(random.choice(string.ascii_lowercase) for x in range(random.randint(16, 20)))
            if self.system == "windows":
                system_drive = os.environ["SYSTEMDRIVE"] + os.sep
                ANALYZER_FOLDER = os.path.join(system_drive, container)
            elif self.system == "linux" or self.system == "darwin":
                ANALYZER_FOLDER = os.path.join(os.environ["HOME"], container)
            else:
                ERROR_MESSAGE = "Unable to identify operating system"
                return False

            try:
                os.makedirs(ANALYZER_FOLDER)
            except OSError as e:
                ERROR_MESSAGE = e
                return False

        return True

    def get_status(self):
        """Get current status.
        @return: status.
        """
        return CURRENT_STATUS

    def get_error(self):
        """Get error message.
        @return: error message.
        """
        return str(ERROR_MESSAGE)

    def add_malware(self, data, name):
        """Get analysis data.
        @param data: analysis data.
        @param name: file name.
        @return: operation status.
        """
        global ERROR_MESSAGE
        data = data.data

        if self.system == "windows":
            root = os.environ["TEMP"]
        elif self.system in("linux", "darwin"):
            root = tempfile.gettempdir()
        else:
            ERROR_MESSAGE = "Unable to write malware to disk because of " \
                            "failed identification of the operating system"
            return False

        file_path = os.path.join(root, name)

        try:
            with open(file_path, "w") as sample:
                sample.write(data)
        except IOError as e:
            ERROR_MESSAGE = "Unable to write sample to disk: {0}".format(e)
            return False

        return True

    def add_config(self, options):
        """Creates analysis.conf file from current analysis options.
        @param options: current configuration options, dict format.
        @return: operation status.
        """
        global ERROR_MESSAGE

        if not isinstance(options, dict):
            return False

        config = configparser.RawConfigParser()
        config.add_section("analysis")

        try:
            for key, value in options.items():
                # Options can be UTF encoded.
                if isinstance(value, str):
                    try:
                        value = value.encode("utf-8")
                    except UnicodeEncodeError:
                        pass

                config.set("analysis", key, value)
            config.set("analysis", "completion_key", COMPLETION_KEY)
            config_path = os.path.join(ANALYZER_FOLDER, "analysis.conf")

            with open(config_path, "w") as config_file:
                config.write(config_file)
        except Exception as e:
            print(e)
            ERROR_MESSAGE = str(e)
            return False

        return True

    def add_analyzer(self, data):
        """Add analyzer.
        @param data: analyzer data.
        @return: operation status.
        """
        data = data.data

        if CURRENT_STATUS != STATUS_INIT:
            return False

        if not self._initialize():
            return False

        try:
            zip_data = BytesIO()
            zip_data.write(data)

            with ZipFile(zip_data, "r") as archive:
                archive.extractall(ANALYZER_FOLDER)
        finally:
            zip_data.close()

        self.analyzer_path = os.path.join(ANALYZER_FOLDER, "analyzer.py")

        return True

    def execute(self):
        """Execute analysis.
        @return: analyzer PID.
        """
        global ERROR_MESSAGE
        global CURRENT_STATUS

        if CURRENT_STATUS != STATUS_INIT:
            return False

        if not self.analyzer_path or not os.path.exists(self.analyzer_path):
            return False

        try:
            proc = subprocess.Popen([sys.executable, self.analyzer_path],
                                    cwd=os.path.dirname(self.analyzer_path))
            self.analyzer_pid = proc.pid
        except OSError as e:
            ERROR_MESSAGE = str(e)
            return False

        CURRENT_STATUS = STATUS_RUNNING

        return self.analyzer_pid

    def complete(self, success=True, error="", results=""):
        """Complete analysis.
        @param success: success status.
        @param error: error status.
        """
        global ERROR_MESSAGE
        global CURRENT_STATUS
        global RESULTS_FOLDER

        if results != COMPLETION_KEY:
            return False

        if success:
            CURRENT_STATUS = STATUS_COMPLETED
        else:
            if error:
                ERROR_MESSAGE = str(error)

            CURRENT_STATUS = STATUS_FAILED

        RESULTS_FOLDER = results

        return True

class MiniHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "Cuckoo Agent"

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

        form = cgi.FieldStorage(fp=self.rfile,
                                headers=self.headers,
                                environ=environ)

        request.client_ip, request.client_port = self.client_address
        request.form = {}
        request.files = {}
        request.method = "POST"

        # Another pretty fancy workaround. Since we provide backwards
        # compatibility with the Old Agent we will get an xmlrpc request
        # from the analyzer when the analysis has finished. Now xmlrpc being
        # xmlrpc we're getting text/xml as content-type which cgi does not
        # handle. This check detects when there is no available data rather
        # than getting a hard exception trying to do so.
        if form.list:
            for key in form.keys():
                value = form[key]
                if value.filename:
                    request.files[key] = value.file
                else:
                    request.form[key] = value.value#.decode("utf8")

        self.httpd.handle(self)

class MiniHTTPServer(object):
    def __init__(self):
        self.handler = MiniHTTPRequestHandler

        # Reference back to the server.
        self.handler.httpd = self

        self.routes = {
            "GET": [],
            "POST": [],
        }

    def run(self, host="0.0.0.0", port=8000):
        self.s = socketserver.TCPServer((host, port), self.handler)
        self.s.allow_reuse_address = True
        self.s.serve_forever()

    def route(self, path, methods=["GET"]):
        def register(fn):
            for method in methods:
                self.routes[method].append((re.compile(path + "$"), fn))
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
            obj.wfile.write(ret.json().encode("utf-8"))
        elif isinstance(ret, send_file):
            ret.write(obj.wfile)

    def shutdown(self):
        # BaseServer also features a .shutdown() method, but you can't use
        # that from the same thread as that will deadlock the whole thing.
        self.s._BaseServer__shutdown_request = True

class jsonify(object):
    """Wrapper that represents Flask.jsonify functionality."""
    def __init__(self, **kwargs):
        self.status_code = 200
        self.values = kwargs

    def init(self):
        pass

    def json(self):
        return json.dumps(self.values)

    def headers(self, obj):
        pass

class send_file(object):
    """Wrapper that represents Flask.send_file functionality."""
    def __init__(self, path):
        self.path = path
        self.status_code = 200

    def init(self):
        if not os.path.isfile(self.path):
            self.status_code = 404
            self.length = 0
        else:
            self.length = os.path.getsize(self.path)

    def write(self, sock):
        if not self.length:
            return

        with open(self.path, "r") as f:
            while True:
                buf = f.read(1024 * 1024)
                if not buf:
                    break

                sock.write(buf)

    def headers(self, obj):
        obj.send_header("Content-Length", self.length)

class request(object):
    form = {}
    files = {}
    client_ip = None
    client_port = None
    method = None
    environ = {
        "werkzeug.server.shutdown": lambda: app.shutdown(),
    }

app = MiniHTTPServer()
state = {}

def json_error(error_code, message):
    r = jsonify(message=message, error_code=error_code)
    r.status_code = error_code
    return r

def json_exception(message):
    r = jsonify(message=message, error_code=500,
                traceback=traceback.format_exc())
    r.status_code = 500
    return r

def json_success(message, **kwargs):
    return jsonify(message=message, **kwargs)

@app.route("/")
def get_index():
    return json_success(
        "Cuckoo Agent!", version=AGENT_VERSION, features=AGENT_FEATURES
    )

@app.route("/status")
def get_status():
    return json_success("Analysis status",
                        status=state.get("status"),
                        description=state.get("description"))

@app.route("/status", methods=["POST"])
def put_status():
    if "status" not in request.form:
        return json_error(400, "No status has been provided")

    state["status"] = request.form["status"]
    state["description"] = request.form.get("description")
    return json_success("Analysis status updated")

@app.route("/logs")
def get_logs():
    return json_success(
        "Agent logs",
        stdout=sys.stdout.getvalue(),
        stderr=sys.stderr.getvalue()
    )

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
    except:
        return json_exception("Error creating directory")

    return json_success("Successfully created directory")

@app.route("/mktemp", methods=["GET", "POST"])
def do_mktemp():
    suffix = request.form.get("suffix", "")
    prefix = request.form.get("prefix", "tmp")
    dirpath = request.form.get("dirpath")

    try:
        fd, filepath = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dirpath)
    except:
        return json_exception("Error creating temporary file")

    os.close(fd)

    return json_success("Successfully created temporary file",
                        filepath=filepath)

@app.route("/mkdtemp", methods=["GET", "POST"])
def do_mkdtemp():
    suffix = request.form.get("suffix", "")
    prefix = request.form.get("prefix", "tmp")
    dirpath = request.form.get("dirpath")

    try:
        dirpath = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dirpath)
    except:
        return json_exception("Error creating temporary directory")

    return json_success("Successfully created temporary directory",
                        dirpath=dirpath)

@app.route("/store", methods=["POST"])
def do_store():
    if "filepath" not in request.form:
        return json_error(400, "No filepath has been provided")

    if "file" not in request.files:
        return json_error(400, "No file has been provided")

    try:
        with open(request.form["filepath"], "wb") as f:
            shutil.copyfileobj(request.files["file"], f, 10*1024*1024)
    except:
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
    except:
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
    except:
        return json_exception("Error removing file or directory")

    return json_success(message)

@app.route("/execute", methods=["POST"])
def do_execute():
    if "command" not in request.form:
        return json_error(400, "No command has been provided")

    # Execute the command asynchronously? As a shell command?
    async_exec = "async" in request.form
    shell = "shell" in request.form

    cwd = request.form.get("cwd")
    stdout = stderr = None

    try:
        if async_exec:
            subprocess.Popen(request.form["command"], shell=shell, cwd=cwd)
        else:
            p = subprocess.Popen(
                request.form["command"], shell=shell, cwd=cwd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = p.communicate()
    except:
        return json_exception("Error executing command")

    return json_success("Successfully executed command",
                        stdout=stdout, stderr=stderr)

@app.route("/execpy", methods=["POST"])
def do_execpy():
    if "filepath" not in request.form:
        return json_error(400, "No Python file has been provided")

    # Execute the command asynchronously? As a shell command?
    async_exec = "async" in request.form

    cwd = request.form.get("cwd")
    stdout = stderr = None

    args = [
        sys.executable,
        request.form["filepath"],
    ]

    try:
        if async_exec:
            subprocess.Popen(args, cwd=cwd)
        else:
            p = subprocess.Popen(args, cwd=cwd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
    except:
        return json_exception("Error executing command")

    return json_success("Successfully executed command",
                        stdout=stdout, stderr=stderr)

@app.route("/pinning")
def do_pinning():
    if "client_ip" in state:
        return json_error(500, "Agent has already been pinned to an IP!")

    state["client_ip"] = request.client_ip
    return json_success("Successfully pinned Agent",
                        client_ip=request.client_ip)

@app.route("/kill")
def do_kill():
    shutdown = request.environ.get("werkzeug.server.shutdown")
    if shutdown is None:
        return json_error(500, "Not running with the Werkzeug server")

    shutdown()
    return json_success("Quit the Cuckoo Agent")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="0.0.0.0")
    parser.add_argument("port", nargs="?", default="8000")
    args = parser.parse_args()

    app.run(host=args.host, port=int(args.port))

