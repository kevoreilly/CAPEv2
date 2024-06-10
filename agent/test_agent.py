"""Tests for the agent."""

import base64
import datetime
import io
import json
import multiprocessing
import os
import pathlib
import random
import shutil
import sys
import tempfile
import time
import unittest
import uuid
import zipfile
from unittest import mock
from urllib.parse import urljoin

import pytest
import requests

import agent

HOST = "127.0.0.1"
PORT = 8000
BASE_URL = f"http://{HOST}:{PORT}"

DIRPATH = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))


def make_temp_name():
    return str(uuid.uuid4())


class TestAgentFunctions:
    @mock.patch("sys.platform", "win32")
    def test_get_subprocess_259(self):
        mock_process_id = 999998
        mock_subprocess = mock.Mock(spec=multiprocessing.Process)
        mock_subprocess.exitcode = 259
        mock_subprocess.pid = mock_process_id
        with mock.patch.dict(agent.state, {"async_subprocess": mock_subprocess}):
            actual = agent.get_subprocess_status()
        assert actual.status_code == 200
        actual_json = json.loads(actual.json())
        assert actual_json["status"] == "running"
        assert actual_json["process_id"] == mock_process_id


@mock.patch("sys.platform", "linux")
class TestMutexAPILinux(unittest.TestCase):
    def test_post_mutex_linux(self):
        """Mutex POSTs are only supported on win32"""
        mutex = self.id()
        agent.request.form["mutex"] = mutex
        response = agent.post_mutex()
        assert isinstance(response, agent.jsonify)
        assert response.status_code == 400

    def test_delete_mutex_linux(self):
        """Mutex DELETEs are only supported on win32"""
        mutex = self.id()
        agent.request.form["mutex"] = mutex
        response = agent.delete_mutex()
        assert isinstance(response, agent.jsonify)
        assert response.status_code == 400


@mock.patch("sys.platform", "win32")
class TestMutexAPIWin32(unittest.TestCase):
    def test_post_mutex_win32_201(self):
        """Mutex POSTs succeed with mocked mutex APIs"""
        mutex = self.id()
        agent.request.form["mutex"] = mutex

        # fake handle mutex based on test id
        hndl_mutex = self.id()

        # mock opening a mutex returning the fake handle
        open_mutex_mock = mock.MagicMock()
        open_mutex_mock.return_value = hndl_mutex, None
        agent.open_mutex = open_mutex_mock

        # mock mutex is acquired
        wait_mutex_mock = mock.MagicMock()
        wait_mutex_mock.return_value = True, None
        agent.wait_mutex = wait_mutex_mock

        response = agent.post_mutex()
        wait_mutex_mock.assert_called_once_with(hndl_mutex)
        assert isinstance(response, agent.jsonify)
        assert response.status_code == 201

    def test_post_mutex_win32_error_mutex_doesnt_exist(self):
        """Mutex POSTs fail gracefully when mutexes won't open"""
        mutex = self.id()
        agent.request.form["mutex"] = mutex

        # mock opening a mutex returning an error
        open_mutex_mock = mock.MagicMock()
        mock_error = mock.MagicMock()
        open_mutex_mock.return_value = None, mock_error
        agent.open_mutex = open_mutex_mock

        response = agent.post_mutex()
        assert response is mock_error

    def test_post_mutex_win32_error_mutex_wait_failed(self):
        """Mutex POSTs fail gracefully when mutex waiting fails"""
        mutex = self.id()
        agent.request.form["mutex"] = mutex

        # fake handle mutex based on test id
        hndl_mutex = self.id()

        # mock opening a mutex returning the fake handle
        open_mutex_mock = mock.MagicMock()
        mock_error = mock.MagicMock()
        open_mutex_mock.return_value = hndl_mutex, None
        agent.open_mutex = open_mutex_mock

        # mock mutex fails to be acquired
        wait_mutex_mock = mock.MagicMock()
        mock_error = mock.MagicMock()
        wait_mutex_mock.return_value = None, mock_error
        agent.wait_mutex = wait_mutex_mock

        response = agent.post_mutex()
        open_mutex_mock.assert_called_once_with(mutex)
        wait_mutex_mock.assert_called_once_with(hndl_mutex)
        assert response is mock_error

    def test_delete_mutex_win32_404(self):
        """Mutex DELETEs 404 when not held"""
        mutex = self.id()
        agent.request.form["mutex"] = mutex
        self.assertNotIn(mutex, agent.agent_mutexes)
        response = agent.delete_mutex()
        assert isinstance(response, agent.jsonify)
        assert response.status_code == 404

    def test_delete_mutex_win32_error_releasing(self):
        mutex = self.id()
        agent.request.form["mutex"] = mutex

        # inject a previously acquired mutex
        hndl_mutex_mock = mock.MagicMock()
        agent.agent_mutexes[mutex] = hndl_mutex_mock

        # mock mutex fails to be released
        release_mutex_mock = mock.MagicMock()
        mock_error = mock.MagicMock()
        release_mutex_mock.return_value = None, mock_error
        agent.release_mutex = release_mutex_mock

        response = agent.delete_mutex()
        assert response is mock_error

    def test_delete_mutex_win32_200(self):
        mutex = self.id()
        agent.request.form["mutex"] = mutex

        # inject a previously acquired mutex
        hndl_mutex_mock = mock.MagicMock()
        agent.agent_mutexes[mutex] = hndl_mutex_mock

        # mock mutex is released
        release_mutex_mock = mock.MagicMock()
        release_mutex_mock.return_value = True, None
        agent.release_mutex = release_mutex_mock

        response = agent.delete_mutex()
        release_mutex_mock.assert_called_once_with(hndl_mutex_mock)
        assert isinstance(response, agent.jsonify)
        assert response.status_code == 200


class TestAgent:
    """Test the agent API."""

    agent_process: multiprocessing.Process = None

    def setup_method(self):
        agent.state = {"status": agent.Status.INIT, "description": "", "async_subprocess": None}
        ev = multiprocessing.Event()
        self.agent_process = multiprocessing.Process(
            target=agent.app.run,
            kwargs={"host": HOST, "port": PORT, "event": ev},
        )
        self.agent_process.start()

        # Wait for http server to start.
        if not ev.wait(5.0):
            raise Exception("Failed to start agent HTTP server")

        # Create temp directory for tests, as makes tidying up easier
        os.mkdir(DIRPATH, 0o777)
        assert os.path.isdir(DIRPATH)

    def teardown_method(self):
        # Remove the temporary directory and files.
        try:
            # Test the kill endpoint, which shuts down the agent service.
            r = requests.get(f"{BASE_URL}/kill")
            assert r.status_code == 200
            assert r.json()["message"] == "Quit the CAPE Agent"
        except requests.exceptions.ConnectionError:
            pass
        shutil.rmtree(DIRPATH, ignore_errors=True)
        assert not os.path.isdir(DIRPATH)

        # Ensure agent process completes; release resources.
        self.agent_process.join()
        self.agent_process.close()

    @staticmethod
    def non_existent_directory():
        root = pathlib.Path(tempfile.gettempdir()).root
        current_pid = os.getpid()
        non_existent = pathlib.Path(root, str(current_pid), str(random.randint(10000, 99999)))
        assert not os.path.isdir(non_existent)
        assert not os.path.exists(non_existent)
        return non_existent

    @staticmethod
    def confirm_status(expected_status):
        """Do a get and check the status."""
        status_url = urljoin(BASE_URL, "status")
        r = requests.get(status_url)
        js = r.json()
        assert js["message"] == "Analysis status"
        assert js["status"] == expected_status
        assert r.status_code == 200
        return js

    @staticmethod
    def create_file(path, contents):
        """Create the named file with the supplied contents."""
        with open(path, "w") as file:
            file.write(contents)
        assert os.path.exists(path)
        assert os.path.isfile(path)

    @staticmethod
    def file_contains(path, expected_contents):
        """Examine the contents of a file."""
        with open(path) as file:
            actual_contents = file.read()
            return bool(expected_contents in actual_contents)

    @classmethod
    def store_file(cls, file_contents):
        """Store a file via the API, with the given contents. Return the filepath."""
        contents = os.linesep.join(file_contents)
        upload_file = {"file": ("name-here-matters-not", contents)}
        filepath = os.path.join(DIRPATH, make_temp_name() + ".py")
        form = {"filepath": filepath}
        js = cls.post_form("store", form, files=upload_file)
        assert js["message"] == "Successfully stored file"
        assert os.path.isfile(filepath)
        assert cls.file_contains(filepath, file_contents[0])
        assert cls.file_contains(filepath, file_contents[-1])
        return filepath

    @staticmethod
    def post_form(url_part, form_data, expected_status=200, files=None):
        """Post to the URL and return the json."""
        url = urljoin(BASE_URL, url_part)
        r = requests.post(url, data=form_data, files=files)
        assert r.status_code == expected_status
        js = r.json()
        return js

    def test_root(self):
        r = requests.get(f"{BASE_URL}/")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "CAPE Agent!"
        assert "version" in js
        assert "features" in js
        assert "execute" in js["features"]
        assert "execpy" in js["features"]
        assert "pinning" in js["features"]

    def test_status_write_valid_text(self):
        """Write a status of 'exception'."""
        # First, confirm the status is NOT 'exception'.
        _ = self.confirm_status(str(agent.Status.INIT))
        form = {"status": "exception"}
        url_part = "status"
        _ = self.post_form(url_part, form)
        _ = self.confirm_status(str(agent.Status.EXCEPTION))

    def test_status_write_valid_number(self):
        """Write a status of '5'."""
        # First, confirm the status is NOT 'exception'.
        _ = self.confirm_status(str(agent.Status.INIT))
        form = {"status": 5}
        url_part = "status"
        _ = self.post_form(url_part, form)
        _ = self.confirm_status(str(agent.Status.EXCEPTION))

    def test_status_write_invalid(self):
        """Fail to provide a valid status."""
        form = {"description": "Test Status"}
        js = self.post_form("status", form, 400)
        assert js["message"] == "No valid status has been provided"

        form = {"status": "unexpected value"}
        js = self.post_form("status", form, 400)
        assert js["message"] == "No valid status has been provided"
        _ = self.confirm_status(str(agent.Status.INIT))

        # Write an unexpected random number.
        form = {"status": random.randint(50, 99)}
        js = self.post_form("status", form, 400)
        assert js["message"] == "No valid status has been provided"
        _ = self.confirm_status(str(agent.Status.INIT))

    def test_logs(self):
        """Test that the agent responds to a request for the logs."""
        r = requests.get(f"{BASE_URL}/logs")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Agent logs"
        assert "stdout" in js
        assert "stderr" in js

    def test_system(self):
        """Test that the agent responds to a request for the system/platform."""
        r = requests.get(f"{BASE_URL}/system")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "System"
        assert "system" in js
        if sys.platform == "win32":
            assert js["system"] == "Windows"
        else:
            assert js["system"] == "Linux"

    def test_environ(self):
        """Test that the agent responds to a request for the environment."""
        r = requests.get(f"{BASE_URL}/environ")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Environment variables"
        assert "environ" in js

    def test_path(self):
        """Test that the agent responds to a request for its path."""
        r = requests.get(f"{BASE_URL}/path")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Agent path"
        assert "filepath" in js
        assert os.path.isfile(js["filepath"])

    def test_mkdir_valid(self):
        """Test that the agent creates a directory."""
        new_dir = os.path.join(DIRPATH, make_temp_name())
        form = {
            "dirpath": new_dir,
            "mode": 0o777,
        }
        js = self.post_form("mkdir", form)
        assert js["message"] == "Successfully created directory"
        assert os.path.exists(new_dir)
        assert os.path.isdir(new_dir)

    def test_mkdir_missing(self):
        """Ensure we get an error returned when the mkdir request fails."""
        form = {}
        js = self.post_form("mkdir", form, 400)
        assert js["message"] == "No dirpath has been provided"

    @pytest.mark.skip("Not many paths are actually invalid")
    def test_mkdir_invalid(self):
        """Ensure we get an error returned when the mkdir request fails."""
        # TODO come up with an invalid directory path for windows / linux
        invalid = ""
        form = {"dirpath": invalid, "mode": 0o777}
        js = self.post_form("mkdir", form, 500)
        assert js["message"] == "Error creating directory"

    def test_mktemp_valid(self):
        form = {
            "dirpath": DIRPATH,
            "prefix": make_temp_name(),
            "suffix": "tmp",
        }
        js = self.post_form("mktemp", form)
        assert js["message"] == "Successfully created temporary file"
        # tempfile.mkstemp adds random characters to suffix, so returned name
        # will be different
        assert "filepath" in js and js["filepath"].startswith(os.path.join(form["dirpath"], form["prefix"]))
        assert os.path.exists(js["filepath"])
        assert os.path.isfile(js["filepath"])

    def test_mktemp_invalid(self):
        """Ensure we get an error returned when the mktemp request fails."""
        dirpath = self.non_existent_directory()
        form = {
            "dirpath": dirpath,
            "prefix": "",
            "suffix": "",
        }
        js = self.post_form("mktemp", form, 500)
        assert js["message"] == "Error creating temporary file"

    def test_mkdtemp_valid(self):
        """Ensure we can use the mkdtemp endpoint."""
        form = {
            "dirpath": DIRPATH,
            "prefix": make_temp_name(),
            "suffix": "tmp",
        }
        js = self.post_form("mkdtemp", form)
        assert js["message"] == "Successfully created temporary directory"
        # tempfile.mkdtemp adds random characters to suffix, so returned name
        # will be different
        assert "dirpath" in js and js["dirpath"].startswith(os.path.join(form["dirpath"], form["prefix"]))
        assert os.path.exists(js["dirpath"])
        assert os.path.isdir(js["dirpath"])

    def test_mkdtemp_invalid(self):
        """Ensure we get an error returned when the mkdtemp request fails."""
        dirpath = self.non_existent_directory()
        assert not dirpath.exists()
        form = {
            "dirpath": dirpath,
            "prefix": "",
            "suffix": "",
        }
        js = self.post_form("mkdtemp", form, 500)
        assert js["message"] == "Error creating temporary directory"

    def test_store(self):
        sample_text = make_temp_name()
        upload_file = {"file": ("ignored", os.linesep.join(("test data", sample_text, "test data")))}
        form = {"filepath": os.path.join(DIRPATH, make_temp_name() + ".tmp")}

        js = self.post_form("store", form, files=upload_file)
        assert js["message"] == "Successfully stored file"
        assert os.path.exists(form["filepath"])
        assert os.path.isfile(form["filepath"])
        assert self.file_contains(form["filepath"], sample_text)

    def test_store_invalid(self):
        # missing file
        form = {"filepath": os.path.join(DIRPATH, make_temp_name() + ".tmp")}
        js = self.post_form("store", form, 400)
        assert js["message"] == "No file has been provided"

        # missing filepath
        upload_file = {"file": ("test_data.txt", "test data\ntest data\n")}
        js = self.post_form("store", {}, 400, files=upload_file)
        assert js["message"] == "No filepath has been provided"

        # destination file path is invalid
        upload_file = {"file": ("test_data.txt", "test data\ntest data\n")}
        form = {"filepath": os.path.join(DIRPATH, make_temp_name(), "tmp")}
        js = self.post_form("store", form, 500, files=upload_file)
        assert js["message"].startswith("Error storing file")

    def test_retrieve(self):
        """Create a file, then try to retrieve it."""
        first_line = make_temp_name()
        last_line = make_temp_name()
        file_contents = os.linesep.join((first_line, "test data", last_line))
        file_path = os.path.join(DIRPATH, make_temp_name() + ".tmp")
        self.create_file(file_path, file_contents)

        form = {"filepath": file_path}
        # Can't use self.post_form here as no json will be returned.
        r = requests.post(f"{BASE_URL}/retrieve", data=form)
        assert r.status_code == 200
        assert first_line in r.text
        assert last_line in r.text
        # Also test the base64-encoded retrieval.
        form["encoding"] = "base64"
        r = requests.post(f"{BASE_URL}/retrieve", data=form)
        assert r.status_code == 200
        decoded = base64.b64decode(r.text + "==").decode()
        assert "test data" in decoded
        assert first_line in decoded
        assert last_line in decoded

    def test_retrieve_invalid(self):
        js = self.post_form("retrieve", {}, 400)
        assert js["message"].startswith("No filepath has been provided")

        # request to retrieve non existent file
        form = {"filepath": os.path.join(DIRPATH, make_temp_name() + ".tmp")}
        # Can't use self.post_form here as no json will be returned.
        r = requests.post(f"{BASE_URL}/retrieve", data=form)
        assert r.status_code == 404

    def test_extract(self):
        """Create a file zip file, then upload and extract the contents."""
        file_dir = make_temp_name()
        file_name = make_temp_name()
        file_contents = make_temp_name()
        zfile = io.BytesIO()
        zf = zipfile.ZipFile(zfile, "w", zipfile.ZIP_DEFLATED, False)
        zf.writestr(os.path.join(file_dir, file_name), file_contents)
        zf.close()
        zfile.seek(0)

        upload_file = {"zipfile": ("test_file.zip", zfile.read())}
        form = {"dirpath": DIRPATH}

        js = self.post_form("extract", form, files=upload_file)
        assert js["message"] == "Successfully extracted zip file"
        expected_path = os.path.join(DIRPATH, file_dir, file_name)
        assert os.path.exists(expected_path)
        assert self.file_contains(expected_path, file_contents)

        # todo should I check the filesytem for the file?

    def test_extract_invalid(self):
        form = {"dirpath": DIRPATH}
        js = self.post_form("extract", form, 400)
        assert js["message"] == "No zip file has been provided"

        upload_file = {"zipfile": ("test_file.zip", "dummy data")}
        js = self.post_form("extract", {}, 400, files=upload_file)
        assert js["message"] == "No dirpath has been provided"

    def test_remove(self):
        tempdir = os.path.join(DIRPATH, make_temp_name())
        tempfile = os.path.join(tempdir, make_temp_name())
        os.mkdir(tempdir, 0o777)
        self.create_file(tempfile, "test data\ntest data\n")

        # delete temp file
        form = {"path": tempfile}
        js = self.post_form("remove", form)
        assert js["message"] == "Successfully deleted file"

        # delete temp directory
        form = {"path": tempdir}
        js = self.post_form("remove", form)
        assert js["message"] == "Successfully deleted directory"

    def test_remove_invalid(self):
        tempdir = os.path.join(DIRPATH, make_temp_name())

        # missing parameter
        form = {}
        js = self.post_form("remove", form, 400)
        assert js["message"] == "No path has been provided"

        # path doesn't exist
        form = {"path": tempdir}
        js = self.post_form("remove", form, 404)
        assert js["message"] == "Path provided does not exist"

    @pytest.mark.skipif(agent.isAdmin(), reason="Test fails if privileges are elevated.")
    def test_remove_system_temp_dir(self):
        # error removing file or dir (permission)
        form = {"path": tempfile.gettempdir()}
        js = self.post_form("remove", form, 500)
        assert js["message"] == "Error removing file or directory"

    def test_async_running(self):
        """Test async execution shows as running after starting."""
        # upload test python file
        file_contents = (
            f"# Comment a random number {random.randint(1000, 9999)}'",
            "import sys",
            "import time",
            "print('hello world')",
            "print('goodbye world', file=sys.stderr)",
            "time.sleep(1)",
            "sys.exit(0)",
        )
        filepath = self.store_file(file_contents)
        form = {"filepath": filepath, "async": 1}

        js = self.post_form("execpy", form)
        assert js["message"] == "Successfully spawned command"
        assert "stdout" not in js
        assert "stderr" not in js
        assert "process_id" in js
        _ = self.confirm_status(str(agent.Status.RUNNING))

    def test_async_complete(self):
        """Test async execution shows as complete after exiting."""
        # upload test python file
        file_contents = (
            f"# Comment a random number {random.randint(1000, 9999)}'",
            "import sys",
            "print('hello world')",
            "sys.exit(0)",
        )
        filepath = self.store_file(file_contents)
        form = {"filepath": filepath, "async": 1}

        js = self.post_form("execpy", form)
        assert js["message"] == "Successfully spawned command"
        # sleep a moment to let it finish
        time.sleep(1)
        _ = self.confirm_status(str(agent.Status.COMPLETE))

    def test_async_failure(self):
        """Test that an unsuccessful script gets a status of 'failed'."""
        # upload test python file. It will sleep, then try to import a nonexistent module.
        file_contents = (
            f"# Comment a random number {random.randint(1000, 9999)}'",
            "import sys",
            "import time",
            "time.sleep(1)",
            "import nonexistent",
            "print('hello world')",
            "print('goodbye world', file=sys.stderr)",
            "sys.exit(0)",
        )

        filepath = self.store_file(file_contents)
        form = {"filepath": filepath, "async": 1}

        js = self.post_form("execpy", form)
        assert js["message"] == "Successfully spawned command"
        assert "stdout" not in js
        assert "stderr" not in js
        assert "process_id" in js
        js = self.confirm_status(str(agent.Status.RUNNING))
        assert "process_id" in js
        time.sleep(2)

        js = self.confirm_status(str(agent.Status.FAILED))
        assert "process_id" not in js

    def test_execute(self):
        """Test executing the 'date' command."""
        if sys.platform == "win32":
            form = {"command": "cmd /c date /t"}
        else:
            form = {"command": "date"}
        js = self.post_form("execute", form)
        assert js["message"] == "Successfully executed command"
        assert "stdout" in js
        assert "stderr" in js
        current_year = datetime.date.today().isoformat()
        assert current_year[:4] in js["stdout"]

    def test_execute_error(self):
        """Expect an error on invalid command to execute."""
        js = self.post_form("execute", {}, 400)
        assert js["message"] == "No command has been provided"

        form = {"command": "ls"}
        js = self.post_form("execute", form, 500)
        assert js["message"] == "Not allowed to execute commands"

    def test_execute_py(self):
        """Test we can execute a simple python script."""
        # The output line endings are different between linux and Windows.
        file_contents = (
            f"# Comment a random number {random.randint(1000, 9999)}'",
            "import sys",
            "print('hello world')",
            "print('goodbye world', file=sys.stderr)",
        )
        filepath = self.store_file(file_contents)

        form = {"filepath": filepath}
        js = self.post_form("execpy", form)
        assert js["message"] == "Successfully executed command"
        assert "stdout" in js and "hello world" in js["stdout"]
        assert "stderr" in js and "goodbye world" in js["stderr"]

    def test_execute_py_error_no_file(self):
        """Ensure we get a 400 back when there's no file provided."""
        # The agent used to return 200 even in various failure scenarios.
        js = self.post_form("execpy", {}, expected_status=400)
        assert js["message"] == "No Python file has been provided"

    def test_execute_py_error_nonexistent_file(self):
        """Ensure we get a 400 back when a nonexistent filename is provided."""
        filepath = os.path.join(DIRPATH, make_temp_name() + ".py")
        form = {"filepath": filepath}
        js = self.post_form("execpy", form, expected_status=400)
        assert js["message"] == "Error executing python command."
        assert "stderr" in js and "No such file or directory" in js["stderr"]
        _ = self.confirm_status(str(agent.Status.FAILED))

    def test_execute_py_error_non_zero_exit_code(self):
        """Ensure we get a 400 back when there's a non-zero exit code."""
        # Run a python script that exits non-zero.
        file_contents = (
            f"# Comment a random number {random.randint(1000, 9999)}'",
            "import sys",
            "print('hello world')",
            "sys.exit(3)",
        )
        filepath = self.store_file(file_contents)
        form = {"filepath": filepath}
        js = self.post_form("execpy", form, expected_status=400)
        assert js["message"] == "Error executing python command."
        assert "hello world" in js["stdout"]
        _ = self.confirm_status(str(agent.Status.FAILED))

    def test_pinning(self):
        r = requests.get(f"{BASE_URL}/pinning")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully pinned Agent"
        assert "client_ip" in js

        # Pinning again causes an error.
        r = requests.get(f"{BASE_URL}/pinning")
        assert r.status_code == 500
        js = r.json()
        assert js["message"] == "Agent has already been pinned to an IP!"
