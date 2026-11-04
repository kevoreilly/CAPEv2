import pytest
import os
import hashlib
import tempfile

# Ideally, this function would be imported from your application code
def check_completion_logic(config):
    complete_folder = hashlib.md5(f"cape-{config.id}".encode()).hexdigest()
    complete_analysis_patterns = [os.path.join(os.environ["TMP"], complete_folder)]
    if "SystemRoot" in os.environ:
        complete_analysis_patterns.append(os.path.join(os.environ["SystemRoot"], "Temp", complete_folder))

    return any(os.path.isdir(path) for path in complete_analysis_patterns)

class MockConfig:
    id = 123

@pytest.fixture
def mock_env(monkeypatch):
    """Pytest fixture to mock environment and create temp dirs."""
    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as sysroot_dir:
        monkeypatch.setenv("TMP", tmp_dir)
        monkeypatch.setenv("SystemRoot", sysroot_dir)
        os.makedirs(os.path.join(sysroot_dir, "Temp"), exist_ok=True)
        yield

def test_completion_folder_in_tmp(mock_env):
    config = MockConfig()
    complete_folder = hashlib.md5(f"cape-{config.id}".encode()).hexdigest()
    path = os.path.join(os.environ["TMP"], complete_folder)
    os.makedirs(path)

    assert check_completion_logic(config) is True

    os.rmdir(path)
    assert check_completion_logic(config) is False


def test_completion_folder_in_systemroot(mock_env):
    config = MockConfig()
    complete_folder = hashlib.md5(f"cape-{config.id}".encode()).hexdigest()
    path = os.path.join(os.environ["SystemRoot"], "Temp", complete_folder)
    os.makedirs(path)

    assert check_completion_logic(config) is True

    os.rmdir(path)
    assert check_completion_logic(config) is False


def test_error_elevation_required():
    from analyzer.windows.lib.common.errors import get_error_string

    err_740 = get_error_string(740)
    assert "ERROR_ELEVATION_REQUIRED" in err_740
    assert "elevation" in err_740.lower()

    err_1223 = get_error_string(1223)
    assert "ERROR_CANCELLED" in err_1223


@pytest.fixture
def mock_archive_package(monkeypatch):
    import importlib.util
    import sys
    import types
    from unittest.mock import MagicMock

    mock_lib_common = types.ModuleType("lib.common")
    monkeypatch.setitem(sys.modules, "lib.common", mock_lib_common)

    mock_constants = types.ModuleType("lib.common.constants")
    for opt in [
        "OPT_ARGUMENTS",
        "OPT_DLLLOADER",
        "OPT_FILE",
        "OPT_FREE",
        "OPT_FUNCTION",
        "OPT_MULTI_PASSWORD",
        "OPT_PASSWORD",
        "OPT_RECURSION_DEPTH",
    ]:
        setattr(mock_constants, opt, opt)
    mock_constants.ARCHIVE_OPTIONS = (
        mock_constants.OPT_FILE,
        mock_constants.OPT_PASSWORD,
        mock_constants.OPT_RECURSION_DEPTH,
    )
    mock_constants.DLL_OPTIONS = (
        mock_constants.OPT_ARGUMENTS,
        mock_constants.OPT_DLLLOADER,
        mock_constants.OPT_FUNCTION,
    )
    monkeypatch.setitem(sys.modules, "lib.common.constants", mock_constants)

    mock_exceptions = types.ModuleType("lib.common.exceptions")

    class CuckooPackageError(Exception):
        pass

    mock_exceptions.CuckooPackageError = CuckooPackageError
    monkeypatch.setitem(sys.modules, "lib.common.exceptions", mock_exceptions)

    mock_abstracts = types.ModuleType("lib.common.abstracts")

    class MockPackage:
        def __init__(self, options=None, config=None):
            self.options = options or {}
            self.config = config

        def execute(self, path, args, interest):
            if "execute_error" in self.options:
                raise self.options["execute_error"]
            if self.options.get("OPT_FREE", False):
                return None
            return 1234

    mock_abstracts.Package = MockPackage
    monkeypatch.setitem(sys.modules, "lib.common.abstracts", mock_abstracts)

    mock_zip_utils = types.ModuleType("lib.common.zip_utils")
    mock_zip_utils.attempt_multiple_passwords = MagicMock()
    mock_zip_utils.extract_archive = MagicMock()
    mock_zip_utils.get_file_names = lambda path, pswd: []
    mock_zip_utils.get_interesting_files = lambda files: files
    mock_zip_utils.upload_extracted_files = MagicMock()
    mock_zip_utils.winrar_extractor = MagicMock()
    monkeypatch.setitem(sys.modules, "lib.common.zip_utils", mock_zip_utils)

    mock_modules_packages = types.ModuleType("modules.packages")
    mock_modules_packages_dll = types.ModuleType("modules.packages.dll")
    mock_modules_packages_dll.DLL_OPTIONS = mock_constants.DLL_OPTIONS
    monkeypatch.setitem(sys.modules, "modules.packages", mock_modules_packages)
    monkeypatch.setitem(sys.modules, "modules.packages.dll", mock_modules_packages_dll)

    spec = importlib.util.spec_from_file_location(
        "archive",
        os.path.join(os.path.dirname(__file__), "../analyzer/windows/modules/packages/archive.py"),
    )
    archive_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive_mod)
    return archive_mod.Archive, CuckooPackageError


def test_archive_multi_file_partial_failure(mock_archive_package):
    Archive, CuckooPackageError = mock_archive_package
    from unittest.mock import MagicMock

    archive_pkg = Archive(options={}, config=MagicMock())

    def mock_execute(root, name, path):
        if name == "failing.exe":
            raise CuckooPackageError("elevation required")
        return [1234]

    archive_pkg.execute_interesting_file = mock_execute
    pids = archive_pkg.execute_files("C:\\extracted", ["failing.exe", "working.exe"])
    assert pids == [1234]


def test_archive_all_files_fail(mock_archive_package):
    Archive, CuckooPackageError = mock_archive_package
    from unittest.mock import MagicMock

    archive_pkg = Archive(options={}, config=MagicMock())

    def mock_execute(root, name, path):
        raise CuckooPackageError("failed execution")

    archive_pkg.execute_interesting_file = mock_execute

    with pytest.raises(CuckooPackageError, match="failed execution"):
        archive_pkg.execute_files("C:\\extracted", ["failing1.exe", "failing2.exe"])


def test_archive_free_mode_success_is_not_an_execution_failure(mock_archive_package):
    Archive, _ = mock_archive_package
    from unittest.mock import MagicMock

    archive_pkg = Archive(options={"OPT_FREE": "yes"}, config=MagicMock())
    archive_pkg.execute_interesting_file = lambda root, name, path: archive_pkg.execute(path, "", path)

    assert archive_pkg.execute_files("C:\\extracted", ["working.exe"]) == []


def test_archive_free_mode_launch_failure_is_still_an_error(mock_archive_package):
    Archive, CuckooPackageError = mock_archive_package
    from unittest.mock import MagicMock

    archive_pkg = Archive(
        options={"OPT_FREE": "yes", "execute_error": CuckooPackageError("failed execution")},
        config=MagicMock(),
    )
    archive_pkg.execute_interesting_file = lambda root, name, path: archive_pkg.execute(path, "", path)

    with pytest.raises(CuckooPackageError, match="failed execution"):
        archive_pkg.execute_files("C:\\extracted", ["failing.exe"])


def test_pipe_forwarder_socket_connect_error(monkeypatch):
    import ctypes
    import os
    import socket
    import struct
    from unittest.mock import MagicMock, patch

    if not hasattr(ctypes, "windll"):
        monkeypatch.setattr(ctypes, "windll", MagicMock(), raising=False)
    if not hasattr(ctypes, "WINFUNCTYPE"):
        monkeypatch.setattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE, raising=False)

    import lib

    analyzer_lib = os.path.abspath(os.path.join(os.path.dirname(__file__), "../analyzer/windows/lib"))
    if analyzer_lib not in lib.__path__:
        lib.__path__.append(analyzer_lib)

    from lib.common.defines import KERNEL32
    from lib.core.pipe import PipeForwarder, open_handles

    def mock_readfile(handle, buf, size, bytes_read, overlapped):
        ctypes.memmove(buf, struct.pack("<I", 4321), 4)
        bytes_read._obj.value = 4
        return 1

    monkeypatch.setattr(KERNEL32, "ReadFile", MagicMock(side_effect=mock_readfile))
    close_mock = MagicMock()
    monkeypatch.setattr(KERNEL32, "CloseHandle", close_mock)

    forwarder = PipeForwarder(pipe_handle=9999, destination=("127.0.0.1", 12345))
    PipeForwarder.active.clear()
    PipeForwarder.sockets.clear()

    # Test socket.timeout (subclass of OSError)
    with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
        forwarder.run()

    close_mock.assert_called_with(9999)
    assert forwarder.active.get(4321) is None
    assert 4321 not in forwarder.sockets
    assert not any(hasattr(s, "fileno") for s in open_handles)

    # Test generic OSError / ConnectionRefusedError
    close_mock.reset_mock()
    with patch("socket.create_connection", side_effect=OSError("connection refused")):
        forwarder.run()

    close_mock.assert_called_with(9999)
    assert forwarder.active.get(4321) is None
    assert 4321 not in forwarder.sockets
