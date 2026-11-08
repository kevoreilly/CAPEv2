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
        "OPT_MAX_EXECUTABLES",
    ]:
        setattr(mock_constants, opt, opt)
    mock_constants.ARCHIVE_OPTIONS = (
        mock_constants.OPT_FILE,
        mock_constants.OPT_PASSWORD,
        mock_constants.OPT_RECURSION_DEPTH,
        mock_constants.OPT_MAX_EXECUTABLES,
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
    archive_mod._module = archive_mod
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


def test_windows_archive_encrypted_headers_extracted_before_discovery(mock_archive_package, tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    Archive, _ = mock_archive_package
    monkeypatch.chdir(tmp_path)
    archive_pkg = Archive(options={"OPT_PASSWORD": ""}, config=MagicMock())
    archive_pkg.get_path_app_in_path = MagicMock(return_value="C:\\Program Files\\7-Zip\\7z.exe")

    def fake_extract(seven_zip_path, path, root, password, try_multiple):
        assert password == "infected"
        target = os.path.join(root, "payload.exe")
        with open(target, "wb") as f:
            f.write(b"MZ\x90\x00")

    monkeypatch.setitem(Archive.start.__globals__, "extract_archive", fake_extract)
    upload_mock = MagicMock()
    monkeypatch.setitem(Archive.start.__globals__, "upload_extracted_files", upload_mock)
    archive_pkg.execute_files = MagicMock(return_value=[4242])

    pids = archive_pkg.start(str(tmp_path / "sample.7z"))
    assert pids == [4242]
    upload_mock.assert_called_once()
    archive_pkg.execute_files.assert_called_once()


def test_windows_archive_winrar_fallback_on_seven_zip_failure(mock_archive_package, tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    Archive, CuckooPackageError = mock_archive_package
    monkeypatch.chdir(tmp_path)
    winrar_bin = tmp_path / "WinRAR.exe"
    winrar_bin.write_bytes(b"MZ")
    archive_pkg = Archive(options={}, config=MagicMock())

    def fake_get_path(app):
        if app == "7z.exe":
            return "C:\\7z.exe"
        if app == "WinRAR.exe":
            return str(winrar_bin)
        raise CuckooPackageError(f"Missing {app}")

    archive_pkg.get_path_app_in_path = MagicMock(side_effect=fake_get_path)
    monkeypatch.setitem(
        Archive.start.__globals__, "extract_archive", MagicMock(side_effect=CuckooPackageError("7z failed"))
    )

    def fake_winrar(winrar, root, path, password="infected", try_multiple=False):
        target = os.path.join(root, "payload.exe")
        with open(target, "wb") as f:
            f.write(b"MZ\x90\x00")
        return ["payload.exe"]

    monkeypatch.setitem(Archive.start.__globals__, "winrar_extractor", fake_winrar)
    monkeypatch.setitem(Archive.start.__globals__, "upload_extracted_files", MagicMock())
    archive_pkg.execute_files = MagicMock(return_value=[1111])

    pids = archive_pkg.start(str(tmp_path / "sample.iso"))
    assert pids == [1111]


def test_windows_archive_wrong_password_reraises_immediately(mock_archive_package, tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    Archive, CuckooPackageError = mock_archive_package
    monkeypatch.chdir(tmp_path)
    archive_pkg = Archive(options={"OPT_PASSWORD": "bad"}, config=MagicMock())
    archive_pkg.get_path_app_in_path = MagicMock(return_value="C:\\7z.exe")
    monkeypatch.setitem(
        Archive.start.__globals__,
        "extract_archive",
        MagicMock(side_effect=CuckooPackageError("Wrong password(s) provided")),
    )
    winrar_mock = MagicMock()
    monkeypatch.setitem(Archive.start.__globals__, "winrar_extractor", winrar_mock)

    with pytest.raises(CuckooPackageError, match="Wrong password"):
        archive_pkg.start(str(tmp_path / "protected.zip"))
    winrar_mock.assert_not_called()


def test_windows_archive_recursion_strips_filepath_and_cleans_nested(mock_archive_package, tmp_path, monkeypatch):
    from pathlib import Path
    import subprocess
    from unittest.mock import MagicMock

    Archive, CuckooPackageError = mock_archive_package
    monkeypatch.chdir(tmp_path)
    archive_pkg = Archive(options={"OPT_RECURSION_DEPTH": 1}, config=MagicMock())
    archive_pkg.get_path_app_in_path = MagicMock(side_effect=lambda a: f"C:\\{a}")

    def fake_extract(seven_zip_path, path, root, password, try_multiple):
        if Path(path).name == "bad_nested.bin":
            raise CuckooPackageError("not an archive")
        with open(os.path.join(root, "0"), "wb") as f:
            f.write(b"text")
        with open(os.path.join(root, "readme.txt"), "wb") as f:
            f.write(b"plain")
        with open(os.path.join(root, "bad_nested.bin"), "wb") as f:
            f.write(b"nested")

    monkeypatch.setitem(Archive.start.__globals__, "extract_archive", fake_extract)
    upload_mock = MagicMock()
    monkeypatch.setitem(Archive.start.__globals__, "upload_extracted_files", upload_mock)
    archive_pkg.execute_files = MagicMock(return_value=[2222])

    def fake_subprocess_run(cmd, **kwargs):
        assert kwargs.get("errors") == "replace"
        res = MagicMock()
        target = cmd[-1]
        if target.endswith("bad_nested.bin"):
            res.stdout = f"{target}: RAR Archive data\n"
        else:
            res.stdout = f"{target}: plain text\n"
        return res

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)
    pids = archive_pkg.start(str(tmp_path / "top_archive.zip"))
    assert pids == [2222]
    root_dir = Path(os.path.join("C:\\", "top_archive.zip"))
    assert list(root_dir.glob("nested-*")) == []


def test_windows_archive_skips_external_symlinks(mock_archive_package, tmp_path, monkeypatch):
    from pathlib import Path
    from unittest.mock import MagicMock

    Archive, _ = mock_archive_package
    monkeypatch.chdir(tmp_path)
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ\x90\x00")
    archive_pkg = Archive(options={}, config=MagicMock())
    archive_pkg.get_path_app_in_path = MagicMock(return_value="C:\\7z.exe")

    def fake_extract(seven_zip_path, path, root, password, try_multiple):
        Path(root, "safe.exe").write_bytes(b"MZ\x90\x00")
        Path(root, "escape.exe").symlink_to(outside)

    monkeypatch.setitem(Archive.start.__globals__, "extract_archive", fake_extract)
    upload_mock = MagicMock()
    monkeypatch.setitem(Archive.start.__globals__, "upload_extracted_files", upload_mock)
    archive_pkg.execute_files = MagicMock(return_value=[3333])

    pids = archive_pkg.start(str(tmp_path / "sample.zip"))
    assert pids == [3333]
    assert upload_mock.call_args.args[1] == ["safe.exe"]


@pytest.fixture
def windows_abstracts_mod(monkeypatch):
    import importlib.util
    import sys
    import types
    from unittest.mock import MagicMock

    for name in [
        "lib",
        "lib.api",
        "lib.api.process",
        "lib.common",
        "lib.common.common",
        "lib.common.constants",
        "lib.common.exceptions",
        "lib.common.parse_pe",
        "lib.core",
        "lib.core.compound",
    ]:
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))

    sys.modules["lib.api.process"].Process = MagicMock()
    sys.modules["lib.common.common"].check_file_extension = lambda p, ext: p
    sys.modules["lib.common.common"].disable_wow64_redirection = lambda fn: fn
    for opt in [
        "OPT_ARGUMENTS",
        "OPT_CURDIR",
        "OPT_DLLLOADER",
        "OPT_FREE",
        "OPT_FUNCTION",
        "OPT_KERNEL_ANALYSIS",
    ]:
        setattr(sys.modules["lib.common.constants"], opt, opt)

    class CuckooPackageError(Exception):
        pass

    sys.modules["lib.common.exceptions"].CuckooPackageError = CuckooPackageError
    sys.modules["lib.common.parse_pe"].choose_dll_export = lambda p: None
    sys.modules["lib.common.parse_pe"].is_pe_image = lambda p: False
    sys.modules["lib.core.compound"].create_custom_folders = MagicMock()

    spec = importlib.util.spec_from_file_location(
        "windows_abstracts",
        os.path.join(os.path.dirname(__file__), "../analyzer/windows/lib/common/abstracts.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_windows_abstracts_execute_interesting_file_containment(windows_abstracts_mod, tmp_path):
    from unittest.mock import MagicMock

    root = tmp_path / "extracted"
    root.mkdir()
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ\x90\x00")
    target = root / "escape.exe"
    target.symlink_to(outside)

    pkg = windows_abstracts_mod.Package(options={})
    pkg.execute = MagicMock()
    with pytest.raises(windows_abstracts_mod.CuckooPackageError, match="outside the extraction directory"):
        pkg.execute_interesting_file(str(root), target.name, str(target))
    pkg.execute.assert_not_called()


def test_windows_abstracts_dllregisterserver_no_unbound_local(windows_abstracts_mod, tmp_path):
    from unittest.mock import MagicMock

    root = tmp_path / "extracted"
    root.mkdir()
    dll = root / "sample.dll"
    dll.write_bytes(b"MZ\x90\x00")

    windows_abstracts_mod.choose_dll_export = lambda p: "DllRegisterServer"
    pkg = windows_abstracts_mod.Package(options={"OPT_ARGUMENTS": "/s"})
    pkg.get_path = MagicMock(return_value="C:\\Windows\\System32\\regsvr32.exe")
    pkg.execute = MagicMock(return_value=9999)

    pid = pkg.execute_interesting_file(str(root), dll.name, str(dll))
    assert pid == 9999
    pkg.execute.assert_called_once_with("C:\\Windows\\System32\\regsvr32.exe", f'/s "{dll}"', str(dll))


def test_windows_abstracts_execute_interesting_file_sets_subfolder_curdir(windows_abstracts_mod, tmp_path):
    from unittest.mock import MagicMock

    root = tmp_path / "extracted"
    sub = root / "nested"
    sub.mkdir(parents=True)
    bat = sub / "run.bat"
    bat.write_text("@echo off\n")

    pkg = windows_abstracts_mod.Package(options={})
    pkg.get_path = MagicMock(return_value="C:\\Windows\\System32\\cmd.exe")
    observed_curdir = []

    def fake_execute(path, args, interest):
        observed_curdir.append(pkg.options.get("OPT_CURDIR"))
        return 1234

    pkg.execute = fake_execute
    pid = pkg.execute_interesting_file(str(root), bat.name, str(bat))
    assert pid == 1234
    assert observed_curdir == [str(sub)]
    assert "OPT_CURDIR" not in pkg.options


def test_windows_zip_utils_extract_archive_and_upload_containment(monkeypatch, tmp_path):
    import importlib.util
    import sys
    import types
    from unittest.mock import MagicMock

    for name in [
        "lib",
        "lib.common",
        "lib.common.constants",
        "lib.common.exceptions",
        "lib.common.hashing",
        "lib.common.results",
    ]:
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))

    sys.modules["lib.common.constants"].OPT_MULTI_PASSWORD = "enable_multi_password"

    class CuckooPackageError(Exception):
        pass

    sys.modules["lib.common.exceptions"].CuckooPackageError = CuckooPackageError
    sys.modules["lib.common.hashing"].hash_file = lambda fn, p: "deadbeef"
    upload_mock = MagicMock()
    sys.modules["lib.common.results"].upload_to_host = upload_mock

    spec = importlib.util.spec_from_file_location(
        "windows_zip_utils",
        os.path.join(os.path.dirname(__file__), "../analyzer/windows/lib/common/zip_utils.py"),
    )
    zip_utils = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(zip_utils)

    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()
    preexisting = extract_dir / "keep.txt"
    preexisting.write_text("keep")

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        res = MagicMock()
        if "-pbad" in cmd:
            (extract_dir / "partial.bin").write_bytes(b"corrupt")
            res.returncode = 2
            res.stderr = b""
            res.stdout = b"ERROR: Wrong password\n"
        else:
            assert not (extract_dir / "partial.bin").exists()
            (extract_dir / "good.exe").write_bytes(b"MZ")
            res.returncode = 0
            res.stderr = b""
            res.stdout = b"Everything is Ok\n"
        return res

    monkeypatch.setattr(zip_utils.subprocess, "run", fake_run)
    zip_utils.extract_archive(
        "C:\\7z.exe",
        str(tmp_path / "sample.7z"),
        str(extract_dir),
        password="bad:secret",
        try_multiple_passwords=True,
    )
    assert preexisting.read_text() == "keep"
    assert (extract_dir / "good.exe").read_bytes() == b"MZ"
    assert not (extract_dir / "partial.bin").exists()

    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (extract_dir / "escape.txt").symlink_to(outside)
    zip_utils.upload_extracted_files(str(extract_dir), ["good.exe", "escape.txt"])
    upload_mock.assert_called_once()
    assert upload_mock.call_args.kwargs["metadata"] == "good.exe"

    sfx_dir = tmp_path / "sfx_extract"
    sfx_dir.mkdir()

    def fake_sfx_run(cmd, **kwargs):
        (sfx_dir / "setup.exe").write_bytes(b"MZ")
        res = MagicMock()
        res.returncode = 1
        res.stderr = b"WARNING: There are some data after the end of the payload data\n"
        res.stdout = b""
        return res

    monkeypatch.setattr(zip_utils.subprocess, "run", fake_sfx_run)
    zip_utils.extract_archive("C:\\7z.exe", str(tmp_path / "installer.run"), str(sfx_dir))
    assert (sfx_dir / "setup.exe").read_bytes() == b"MZ"


def test_windows_archive_caps_max_executables(mock_archive_package, tmp_path, monkeypatch):
    from pathlib import Path
    from unittest.mock import MagicMock

    Archive, _ = mock_archive_package
    monkeypatch.chdir(tmp_path)
    archive_pkg = Archive(options={"OPT_MAX_EXECUTABLES": 2}, config=MagicMock())
    archive_pkg.get_path_app_in_path = MagicMock(return_value="C:\\7z.exe")

    def fake_extract(seven_zip_path, path, root, password, try_multiple):
        for idx in range(5):
            Path(root, f"p{idx}.exe").write_bytes(b"MZ\x90\x00")

    monkeypatch.setitem(Archive.start.__globals__, "extract_archive", fake_extract)
    monkeypatch.setitem(Archive.start.__globals__, "upload_extracted_files", MagicMock())
    archive_pkg.execute_interesting_file = MagicMock(side_effect=[101, 102, 103, 104, 105])

    pids = archive_pkg.start(str(tmp_path / "many.zip"))
    assert pids == [101, 102]
    assert archive_pkg.execute_interesting_file.call_count == 2

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
